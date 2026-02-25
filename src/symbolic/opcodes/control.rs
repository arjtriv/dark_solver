use crate::symbolic::state::SymbolicMachine;
use revm::interpreter::Interpreter;
use revm::primitives::U256;
use revm::{Database, EvmContext};
use z3::ast::{Ast, BV};

pub fn handle_control<'ctx, DB: Database>(
    machine: &mut SymbolicMachine<'ctx>,
    interpreter: &mut Interpreter,
    _context: &mut EvmContext<DB>,
    opcode: u8,
) {
    match opcode {
        // STOP (0x00) - Clean halt
        0x00 => {
            // Execution stops cleanly - no stack effect
        }
        // JUMPDEST (0x5B) - Valid jump target marker
        0x5B => {
            // No stack effect, just a marker
        }
        // JUMP (0x56)
        0x56 => {
            machine.sym_stack.pop();
        }
        // JUMPI (0x57)
        0x57 => {
            let _target = machine.sym_stack.pop();
            let condition = machine.sym_stack.pop();
            let c_bv = condition;

            let pc = interpreter.program_counter();

            let jump_sat = {
                machine.solver.push();
                machine.solver_depth += 1;
                machine.solver.assert(
                    &c_bv
                        ._eq(&crate::symbolic::utils::math::zero(machine.context))
                        .not(),
                );
                let res = machine.solver.check() == z3::SatResult::Sat;
                machine.solver.pop(1);
                machine.solver_depth -= 1;
                res
            };

            let fallthrough_sat = {
                machine.solver.push();
                machine.solver_depth += 1;
                machine
                    .solver
                    .assert(&c_bv._eq(&crate::symbolic::utils::math::zero(machine.context)));
                let res = machine.solver.check() == z3::SatResult::Sat;
                machine.solver.pop(1);
                machine.solver_depth -= 1;
                res
            };

            let decision = if let Some(&forced) = machine.path_constraints.get(&pc) {
                forced
            } else if jump_sat && fallthrough_sat {
                // PATH EXPLOSION PROTECTION: Max Branch Depth
                if (machine.solver_depth as usize) >= machine.max_solver_depth {
                    eprintln!(
                        "[WARN] Max Solver Depth ({}) Exceeded at PC {}. Pruning Branch.",
                        machine.max_solver_depth, pc
                    );
                    // Prune: Choose Fallthrough (false) to avoid stack explosion
                    false
                } else if machine.total_branches >= machine.max_branches {
                    eprintln!(
                        "[WARN] Max Branch Budget ({}) Exceeded at PC {}. Pruning Branch.",
                        machine.max_branches, pc
                    );
                    false
                } else {
                    machine.unexplored_branches.push((pc, false));
                    machine.total_branches += 1;
                    true
                }
            } else {
                jump_sat
            };

            if decision {
                // Push before assert so the constraint lives in the new solver scope
                // and can be properly reverted by restore()/solver.pop().
                if jump_sat && fallthrough_sat {
                    machine.solver.push();
                    machine.solver_depth += 1;
                    machine.branch_pushes += 1;
                }

                let constraint = c_bv
                    ._eq(&crate::symbolic::utils::math::zero(machine.context))
                    .not();
                machine.solver.assert(&constraint);

                let _ = interpreter
                    .stack_mut()
                    .set(1, revm::primitives::U256::from(1));
            } else {
                // Push before assert so the constraint lives in the new solver scope
                // and can be properly reverted by restore()/solver.pop().
                if jump_sat && fallthrough_sat {
                    machine.solver.push();
                    machine.solver_depth += 1;
                    machine.branch_pushes += 1;
                }

                let constraint = c_bv._eq(&crate::symbolic::utils::math::zero(machine.context));
                machine.solver.assert(&constraint);

                let _ = interpreter.stack_mut().set(1, revm::primitives::U256::ZERO);
            }
        }
        // PC (0x58)
        0x58 => {
            let pc = interpreter.program_counter();
            machine
                .sym_stack
                .push(BV::from_u64(machine.context, pc as u64, 256));
        }
        // GAS (0x5a)
        0x5a => {
            machine.sym_stack.push(machine.gas_remaining.clone());
        }

        // POP (0x50)
        0x50 => {
            machine.sym_stack.pop();
        }
        // RETURNDATASIZE (0x3D)
        0x3D => {
            let size = machine.last_return_data.1.clone();
            machine.sym_stack.push(size);
        }
        // RETURNDATACOPY (0x3E)
        0x3E => {
            let dest = machine.sym_stack.pop();
            let off = machine.sym_stack.pop();
            let len = machine.sym_stack.pop();

            // 1. Revert Logic (No longer unconditional Assert)
            // If safe_end > size, we should Revert.
            // We remove the Assert to allow the solver to see the Revert path.
            let safe_end = off.bvadd(&len);
            let size = &machine.last_return_data.1;

            // Symbolic Check: Is the copy valid?
            let _in_bounds = safe_end.bvule(size);

            // 2. Symbolic Copy
            let safe_limit = crate::symbolic::utils::math::bounded_len(&len, 1024);

            for i in 0..safe_limit {
                // Source Index: off + i
                let src_idx = off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));
                // Read from Return Data Array (Symbolic)
                let val = machine
                    .last_return_data
                    .0
                    .select(&src_idx)
                    .as_bv()
                    .unwrap_or_else(|| BV::from_u64(machine.context, 0, 8));

                // Destination Index: dest + i
                let dest_idx = dest.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));

                // Fetch Old Value (8-bit, same sort as val from array select)
                let old_val = machine.read_byte(dest_idx.clone());

                let i_bv = crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from(i));
                let i_lt_len = i_bv.bvult(&len);

                // Guard: only write if i < len. Both val and old_val are BV<8>.
                let val_to_write = i_lt_len.ite(&val, &old_val);

                machine.write_byte(dest_idx, val_to_write);
            }
        }
        // INVALID (0xFE)
        0xFE => {
            machine.reverted = true;
        }
        // SELFDESTRUCT (0xFF)
        0xFF => {
            let _beneficiary = machine.sym_stack.pop();
            let destroyed_contract = interpreter.contract().target_address;
            machine.record_selfdestruct(destroyed_contract);
        }
        // LOG0-LOG4 (0xA0..=0xA4)
        0xA0..=0xA4 => {
            let n = opcode - 0xA0;
            machine.sym_stack.pop(); // offset
            machine.sym_stack.pop(); // length
            for _ in 0..n {
                machine.sym_stack.pop(); // topics
            }
        }
        _ => {}
    }
}
