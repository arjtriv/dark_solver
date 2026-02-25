use revm::interpreter::Interpreter;
use revm::primitives::U256;
use revm::{Database, EvmContext};
use z3::ast::{Ast, BV};

use crate::symbolic::patterns::{PatternInference, SHA3Trace};
use crate::symbolic::state::{SymbolicMachine, MAX_JOURNAL_ENTRIES};
use crate::symbolic::z3_ext::u256_from_bv;

pub fn handle_memory<'ctx, DB: Database>(
    machine: &mut SymbolicMachine<'ctx>,
    interpreter: &mut Interpreter,
    _context: &mut EvmContext<DB>,
    opcode: u8,
) {
    match opcode {
        // SHA3 (0x20)
        0x20 => {
            let offset_bv = machine.sym_stack.pop();
            let size_bv = machine.sym_stack.pop();

            // GLOBAL KNOWLEDGE: Hook into Oracle
            // 1. Try to read concrete bytes if possible
            if let Some(sz_u64) = u256_from_bv(&size_bv).and_then(|v| u64::try_from(v).ok()) {
                if sz_u64 <= 128 {
                    // Reasonable limit for detailed analysis
                    // Read bytes for Oracle
                    let mut preimage = Vec::with_capacity(sz_u64 as usize);
                    let mut all_concrete = true;
                    for i in 0..sz_u64 {
                        let idx = offset_bv.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                            machine.context,
                            U256::from(i),
                        ));
                        let b = machine.read_byte(idx);
                        if u256_from_bv(&b).is_none() {
                            all_concrete = false;
                        }
                        preimage.push(b);
                    }

                    // If fully concrete, compute real hash and Assert(UF == Real)
                    // We do this LATER after we decide WHICH UF to use.

                    // Content-based UFs: read words from the hashed region.
                    // Covers sizes 32, 64, 96, 128 via sliced UFs for sound content-dependent hashing.
                    let num_words = sz_u64.div_ceil(32) as usize;
                    let input_values = if (1..=4).contains(&num_words) {
                        let mut words = Vec::with_capacity(num_words);
                        for w in 0..num_words {
                            let w_off = offset_bv.bvadd(&BV::from_u64(
                                machine.context,
                                (w as u64) * 32,
                                256,
                            ));
                            words.push(machine.read_word(w_off));
                        }
                        Some(words)
                    } else {
                        None
                    };

                    let uf_term = machine.keccak.apply_symbolic(input_values);

                    // Record Logic
                    if all_concrete {
                        let mut bytes = Vec::with_capacity(sz_u64 as usize);
                        for b in &preimage {
                            if let Some(byte_u64) =
                                u256_from_bv(b).and_then(|v| u8::try_from(v).ok())
                            {
                                bytes.push(byte_u64);
                            } else {
                                all_concrete = false;
                                break;
                            }
                        }

                        if !all_concrete {
                            machine.sym_stack.push(uf_term);
                            return;
                        }

                        let real_hash = revm::primitives::keccak256(&bytes);
                        let real_hash_bv = crate::symbolic::z3_ext::bv_from_u256(
                            machine.context,
                            U256::from_be_bytes(real_hash.0),
                        );

                        // Inject "Glass Box" Constraint: UF(x) == Concrete(x)
                        machine.solver.assert(&uf_term._eq(&real_hash_bv));

                        // NEW: Runtime Preimage Recording
                        // If we see a concrete SHA3, we record it.
                        // SLOAD will later pick this up to resolve symbolic slots matching this hash.
                        let hex_preimage: String =
                            bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        machine.oracle.record_hash(
                            U256::from_be_bytes(real_hash.0),
                            format!("runtime_sha3_{}", hex_preimage),
                        );
                    }

                    // --- INJECTIVITY & PATTERN RECOGNITION (P0) ---
                    let trace = SHA3Trace {
                        preimage: preimage.clone(),
                        hash: uf_term.clone(),
                        size: size_bv.clone(),
                        pc: interpreter.program_counter(),
                    };

                    machine.record_sha3(trace.clone());

                    if let Some(pattern) = PatternInference::infer(
                        Some(&machine.detected_patterns),
                        &machine.sha3_trace,
                        &trace,
                    ) {
                        // Check if hash is concrete to use as key
                        if u256_from_bv(&uf_term).is_some() {
                            // Logic flaw: Hash is 256 bits, might not fit u64
                            // We prefer U256 keys. Check u256_from_bv logic or just use if concrete.
                            // Actually `machine.detected_patterns` keys are U256.
                            // We need to extract U256 from BV if constant.

                            // Attempt extraction
                            // (Simplification: only extract if fully concrete for now, or just log)
                            // For now, let's just log it.
                            println!(
                                "[SCAN] Detected Storage Pattern: {:?} at Hash derived from {:?}",
                                pattern, trace.preimage
                            );
                        }

                        // To store it, we need the hash as U256.
                        // `uf_term` is the hash.
                        // We can only store it in the map if the hash is concrete (runtime knowable).
                        // If the hash is symbolic, we can't key a HashMap<U256, ...> with it easily during execution unless we solve for it.
                        // However, for FlatMapping, the hash depends on concrete keys usually?
                        // Wait, Pattern Inference is mostly useful when we know the Slot Index.

                        // Extract a concrete hash key only when the preimage is fully concrete.
                        if all_concrete {
                            let real_hash = revm::primitives::keccak256(
                                preimage
                                    .iter()
                                    .filter_map(|b| {
                                        u256_from_bv(b).and_then(|v| u8::try_from(v).ok())
                                    })
                                    .collect::<Vec<_>>(),
                            );
                            let key = U256::from_be_bytes(real_hash.0);
                            machine.detected_patterns.insert(key, pattern);
                        }
                    }
                    // --------------------------------

                    machine.sym_stack.push(uf_term);
                    return;
                }
            }

            // Fallback for unbounded/unknown size: fresh symbolic constant
            let uf_term = machine.keccak.apply_symbolic(None);
            machine.sym_stack.push(uf_term);
        }
        // MLOAD (0x51)
        0x51 => {
            let offset_bv = machine.sym_stack.pop();
            // Max offset touched is offset + 32
            let end_off = offset_bv.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                machine.context,
                U256::from(32),
            ));
            machine.update_max_offset(end_off);

            let word = machine.read_word(offset_bv);
            machine.sym_stack.push(word);
        }
        // MSTORE (0x52)
        0x52 => {
            let offset = machine.sym_stack.pop();
            let value = machine.sym_stack.pop();

            let end_off = offset.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                machine.context,
                U256::from(32),
            ));
            machine.update_max_offset(end_off);

            machine.write_word(offset, value);
        }
        // MSTORE8 (0x53)
        0x53 => {
            let offset = machine.sym_stack.pop();
            let value = machine.sym_stack.pop();

            let end_off = offset.bvadd(&crate::symbolic::utils::math::one(machine.context));
            machine.update_max_offset(end_off);

            machine.write_byte(offset, value);
        }
        // MSIZE (0x59)
        0x59 => {
            // MSIZE = (max_memory_offset + 31) / 32 * 32
            let max_off = &machine.max_memory_offset;
            let n31 = crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from(31));
            let n32 = crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from(32));

            // Logic: ((max + 31) / 32) * 32
            // Use bvudiv for unsigned checks
            let msize = max_off.bvadd(&n31).bvudiv(&n32).bvmul(&n32);
            machine.sym_stack.push(msize);
        }
        // SLOAD (0x54)
        0x54 => {
            let slot_bv = machine.sym_stack.pop();
            let addr = interpreter.contract().target_address;

            // Lazy Keccak Expansion:
            // Only instantiate chain injectivity for the slot currently being queried.
            machine.materialize_keccak_chain_for_slot(&slot_bv);

            // ALGEBRAIC STORAGE LIFTING:
            // We temporarily take the strategy to avoid borrow conflicts.
            // The strategy handles Pattern Resolution -> Shadow State -> Flat Fallback.
            let Some(mut strategy) = machine.storage_strategy.take() else {
                machine.reverted = true;
                interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
                return;
            };
            let res = strategy.sload(machine, addr, slot_bv);
            machine.storage_strategy = Some(strategy);

            machine.sym_stack.push(res);
        }
        // SSTORE (0x55)
        0x55 => {
            let key = machine.sym_stack.pop();
            let val = machine.sym_stack.pop();

            let addr = interpreter.contract().target_address;

            // 1. Update Shadow State (Algebraic Lifting)
            // We ignore the result (it mutates internal shadow state if pattern matches)
            let Some(mut strategy) = machine.storage_strategy.take() else {
                machine.reverted = true;
                interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
                return;
            };
            strategy.sstore(machine, addr, key.clone(), val.clone());
            machine.storage_strategy = Some(strategy);

            machine.mark_reentrancy_sstore(&key);
            machine.mark_delegatecall_sstore(&key);

            if machine.storage_log.len() >= MAX_JOURNAL_ENTRIES {
                eprintln!(
                    "[WARN] OOM Protection: Max Storage Log Entries Exceeded ({})",
                    MAX_JOURNAL_ENTRIES
                );
                machine.reverted = true;
                // Fail closed if the storage journal capacity is exceeded.
                interpreter.instruction_result = revm::interpreter::InstructionResult::Revert;
            } else {
                let addr = interpreter.contract().target_address;
                machine.storage_log.push((key.clone(), val.clone()));

                let current_storage = machine.get_storage(addr);
                let new_storage = current_storage.store(&key, &val);
                machine.set_storage_array(addr, new_storage);

                // HEURISTIC: OpenZeppelin ReentrancyGuard Support
                // _status: 1 = _NOT_ENTERED, 2 = _ENTERED
                // If we see a write of 2, we lock. If 1, we unlock.
                // We don't know WHERE the status slot is, but if we see a write of 2 to ANY slot,
                // followed by a call... it's a strong signal.
                // To be precise: We map the *slot* to the lock.
                // But simpler: If the contract writes 2 to a slot, we assume that slot IS the guard.

                if let Some(val_u64) = u256_from_bv(&val).and_then(|v| u64::try_from(v).ok()) {
                    if val_u64 == 2 {
                        // _ENTERED
                        machine.reentrancy_lock.insert(addr, true);
                    } else if val_u64 == 1 {
                        // _NOT_ENTERED
                        machine.reentrancy_lock.insert(addr, false);
                    }
                }
            }
        }
        _ => {}
    }
}
