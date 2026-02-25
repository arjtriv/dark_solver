use crate::symbolic::opcodes;
use crate::symbolic::state::{CallFrame, SymbolicMachine, SymbolicStack, MAX_JOURNAL_DEPTH};
use crate::symbolic::utils::gas::get_opcode_gas;
use revm::{interpreter::Interpreter, Database, EvmContext, Inspector};
use z3::ast::BV;

impl<'ctx, DB: Database> Inspector<DB> for SymbolicMachine<'ctx> {
    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut revm::interpreter::CallInputs,
    ) -> Option<revm::interpreter::CallOutcome> {
        // SHORT-CIRCUIT: Protocol model already handled this call in handle_calls.
        // Return success immediately to prevent REVM from executing the actual sub-call,
        // which would overwrite the model's symbolic state (memory writes, stack values).
        if self.call_handled {
            self.call_handled = false;
            self.next_call_target.take();
            self.next_call_args.take();
            self.next_call_site_pc.take();
            self.pending_calls.pop();
            self.delegatecall_depth = self.delegatecall_depth.saturating_sub(1);
            return Some(revm::interpreter::CallOutcome {
                result: revm::interpreter::InterpreterResult {
                    result: revm::interpreter::InstructionResult::Return,
                    output: revm::primitives::Bytes::new(),
                    gas: revm::interpreter::Gas::new(inputs.gas_limit),
                },
                memory_offset: 0..0,
            });
        }

        if matches!(inputs.scheme, revm::interpreter::CallScheme::DelegateCall) {
            self.delegatecall_depth = self.delegatecall_depth.saturating_add(1);
        }

        // Memory/call-depth circuit breaker: use `frames.len()` as the source of truth.
        if self.frames.len() >= MAX_JOURNAL_DEPTH {
            eprintln!(
                "[WARN] OOM Protection: Max Call Depth Exceeded ({})",
                MAX_JOURNAL_DEPTH
            );
            return Some(revm::interpreter::CallOutcome {
                result: revm::interpreter::InterpreterResult {
                    result: revm::interpreter::InstructionResult::CallTooDeep,
                    output: revm::primitives::Bytes::new(),
                    gas: revm::interpreter::Gas::new(0),
                },
                memory_offset: 0..0,
            });
        }

        // REENTRANCY DETECTION: Runs here (Inspector::call) so call_path
        // persists across the actual sub-call execution lifetime.
        if let Some((target_addr, is_static)) = self.next_call_target.take() {
            let Some(call_site_pc) = self.next_call_site_pc.take() else {
                eprintln!(
                    "[WARN] Missing reentrancy call-site PC; aborting branch instead of defaulting to pc=0"
                );
                return Some(revm::interpreter::CallOutcome {
                    result: revm::interpreter::InterpreterResult {
                        result: revm::interpreter::InstructionResult::Revert,
                        output: revm::primitives::Bytes::new(),
                        gas: revm::interpreter::Gas::new(0),
                    },
                    memory_offset: 0..0,
                });
            };

            // 1. Recursion Check: target already in call path
            if self.call_path.contains(&target_addr) {
                self.reentrancy_detected = true;
            }

            // 2. Read-Only Reentrancy Check
            if let Some(&locked) = self.reentrancy_lock.get(&target_addr) {
                if locked && is_static {
                    self.reentrancy_detected = true;
                }
            }

            // 3. Track attacker callback
            let origin = self.effective_tx_origin(_context.inner.env.tx.caller);
            if !is_static && target_addr == origin {
                let modeled_reentry = self.fork_reentrancy_branch(call_site_pc);
                if !modeled_reentry {
                    self.active_reentrancy_branch_key = None;
                }
            }

            // Push BEFORE frame save so it persists during sub-call
            self.call_path.push(target_addr);
        }

        // 1. Save Parent Frame
        self.journal.push(Vec::new());

        let current_frame = CallFrame {
            stack: self.sym_stack.clone(),
            memory: self.memory.clone(),
            address: self.effective_tx_origin(_context.inner.env.tx.caller),
            calldata: self.calldata.clone(),
            pc: 0,
            max_memory_offset: self.max_memory_offset.clone(),
        };
        self.frames.push(current_frame);

        // Transfer symbolic arguments into the callee context (O(1) array clone).
        // Pass a snapshot of parent memory plus the calldata offset.
        let new_calldata = if let Some((offset_bv, _len_bv)) = self.next_call_args.take() {
            (self.memory.clone(), offset_bv)
        } else {
            // Fallback for weird edge cases (shouldn't happen in standard calls)
            (self.zero_memory(), BV::from_u64(self.context, 0, 256))
        };

        // 2. Initialize Sub-call state
        self.sym_stack = SymbolicStack::new(self.context);
        self.calldata = new_calldata;

        // Create a FRESH zero-initialized array for the new call context
        self.memory = self.zero_memory();

        // Reset Max Memory Offset for new context (it's per context)
        self.max_memory_offset = BV::from_u64(self.context, 0, 256);

        // Clear return data buffers for new context
        let empty_arr = self.fresh_byte_array("empty_ret");
        let zero_len = BV::from_u64(self.context, 0, 256);

        self.last_return_data = (empty_arr.clone(), zero_len.clone());
        self.current_return_data = (empty_arr, zero_len);

        // Handle Call Value symbolically
        if let revm::interpreter::CallValue::Transfer(val) = inputs.value {
            let bv_val = crate::symbolic::z3_ext::bv_from_u256(self.context, val);
            self.call_value = Some(bv_val);
        }

        None
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &revm::interpreter::CallInputs,
        outcome: revm::interpreter::CallOutcome,
    ) -> revm::interpreter::CallOutcome {
        // Capture result from this frame
        let result_data = self.current_return_data.clone();
        let was_reverted = match outcome.result.result {
            revm::interpreter::InstructionResult::Revert
            | revm::interpreter::InstructionResult::CallTooDeep
            | revm::interpreter::InstructionResult::OutOfGas
            | revm::interpreter::InstructionResult::StackOverflow
            | revm::interpreter::InstructionResult::StackUnderflow => true,
            _ => false, // Success or Stop or Return
        };

        // Restore Parent Frame
        if let Some(parent) = self.frames.pop() {
            self.sym_stack = parent.stack;
            self.memory = parent.memory;
            self.calldata = parent.calldata;
            self.max_memory_offset = parent.max_memory_offset;

            self.last_return_data = result_data.clone();

            // Handle pending call return writing (Black Box vs White Box integration)
            if let Some((ret_off, ret_size)) = self.pending_calls.pop() {
                let _old_succ = self.sym_stack.pop();
                let mut effective_reverted = was_reverted;

                // Write Return Data to Parent Memory (ONLY IF SUCCESS).
                // If we cannot decode the byte-typed Z3 Array, fail-closed as a revert.
                if !effective_reverted {
                    // Use a bounded loop length for symbolic sizes; default to the configured limit.
                    // 4096 matches the safe memory loop limit used by call handling.
                    let safe_loop_limit =
                        crate::symbolic::utils::math::bounded_len(&ret_size, 4096);

                    for i in 0..safe_loop_limit {
                        // Source: result_data.0 (Array) at index i
                        // Check: i < result_data.1 (Sym Len)
                        let i_bv = BV::from_u64(self.context, i as u64, 256);
                        let is_in_bounds = i_bv.bvult(&result_data.1);

                        let dest_idx = ret_off.bvadd(&i_bv);
                        let Some(val_to_write) = result_data.0.select(&i_bv).as_bv() else {
                            effective_reverted = true;
                            break;
                        }; // BV<8>

                        let current_mem_val = self.read_byte(dest_idx.clone()); // BV<8>
                        let final_val = is_in_bounds.ite(&val_to_write, &current_mem_val); // BV<8>

                        self.write_byte(dest_idx.clone(), final_val);

                        // Update max offset
                        let end_off = dest_idx.bvadd(&BV::from_u64(self.context, 1, 256));
                        self.update_max_offset(end_off);
                    }
                }

                let succ_bv = if effective_reverted {
                    z3::ast::BV::from_u64(self.context, 0, 256)
                } else {
                    z3::ast::BV::from_u64(self.context, 1, 256)
                };
                self.sym_stack.push(succ_bv);
                if effective_reverted {
                    self.reverted = true;
                }
            }
        }

        // Pop call_path: matches the push in Inspector::call
        self.call_path.pop();
        if matches!(_inputs.scheme, revm::interpreter::CallScheme::DelegateCall) {
            self.delegatecall_depth = self.delegatecall_depth.saturating_sub(1);
        }

        outcome
    }

    fn step(&mut self, interpreter: &mut Interpreter, context: &mut EvmContext<DB>) {
        let opcode = interpreter.current_opcode();
        self.last_opcode = opcode;

        // PATH EXPLOSION MITIGATION: Loop Detection
        let pc = interpreter.program_counter();
        let count = self.mark_visited_pc(pc);

        if count > self.max_loop_iterations {
            interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
            self.reverted = true;
            return;
        }

        // Guided branch pruning: stop immediately on statically identified dead-end PCs.
        // If this PC was identified as a guaranteed revert sink during static analysis,
        // kill the branch immediately to save solver cycles.
        if self.dead_end_pcs.contains(&pc) {
            interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
            self.reverted = true;
            return;
        }

        // VISITED PCS OOM PROTECTION
        if self.visited_pcs.len() > self.max_visited_pcs {
            eprintln!(
                "[WARN] OOM Protection: Max Visited PCs Exceeded ({})",
                self.max_visited_pcs
            );
            interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
            self.reverted = true;
            return;
        }

        // GAS MODELING: Dynamic Deduction
        let gas_cost = get_opcode_gas(opcode); // Helper function
        let cost_bv = BV::from_u64(self.context, gas_cost, 256);
        self.gas_remaining = self.gas_remaining.bvsub(&cost_bv);

        // OOG Check: We MUST constrain gas_remaining >= 0
        // Otherwise the solver will explore paths where we use more gas than available.
        let zero = crate::symbolic::utils::math::zero(self.context);
        self.solver.assert(&self.gas_remaining.bvsge(&zero));

        opcodes::dispatch(self, interpreter, context, opcode);

        // Fail-closed on EVM stack underflow: treat this path as reverted and stop exploring it.
        if self.sym_stack.take_underflowed() {
            interpreter.instruction_result = revm::interpreter::InstructionResult::StackUnderflow;
            self.reverted = true;
            return;
        }

        // Invariant-Targeted Reentrancy Prune:
        // Keep reentrancy branches only when they touched solvency/K-constraint-related state.
        if self.frames.is_empty()
            && matches!(opcode, 0x00 | 0xF3 | 0xFF)
            && self.should_prune_reentrancy_path()
        {
            interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
            self.reverted = true;
        }
    }

    fn step_end(&mut self, interpreter: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let opcode = self.last_opcode;
        // PUSH0 (0x5f) .. PUSH32 (0x7f)
        if let 0x5f..=0x7f = opcode {
            // Concrete interpreter has pushed the value. We sync it.
            if let Ok(val) = interpreter.stack().peek(0) {
                let z3_val = crate::symbolic::z3_ext::bv_from_u256(self.context, val);
                self.sym_stack.push(z3_val);
            }
        }
    }
}
