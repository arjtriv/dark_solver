use crate::symbolic::state::SymbolicMachine;

pub fn handle_stack<'ctx>(machine: &mut SymbolicMachine<'ctx>, opcode: u8) {
    match opcode {
        // DUP1..DUP16 (0x80..0x8f)
        0x80..=0x8f => {
            const DUP_BASE: u8 = 0x80;
            // DUP1 (0x80) -> Offset 0 (Top)
            let offset = (opcode - DUP_BASE) as usize;
            // Production safety: stack underflow should kill the path, not the process.
            if machine.sym_stack.len() <= offset {
                machine.reverted = true;
                return;
            }
            let val = machine.sym_stack.peek(offset);
            machine.sym_stack.push(val);
        }
        // SWAP1..SWAP16 (0x90..0x9f)
        0x90..=0x9f => {
            const SWAP_BASE: u8 = 0x90;
            // SWAP1 (0x90) -> Offset 1 (Swap Top with Top-1)
            let offset = (opcode - SWAP_BASE) as usize + 1;
            let len = machine.sym_stack.stack.len();

            // Violation 6 Fix: Check bounds
            // We need at least offset + 1 items.
            // e.g. SWAP1 (offset 1) needs 2 items. len >= 2.
            if len <= offset {
                machine.reverted = true;
                return;
            }
            // stack.swap takes (a, b) indices.
            // top is len-1. Target is len-1-offset.
            machine.sym_stack.stack.swap(len - 1, len - 1 - offset);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::z3_ext::u256_from_bv;
    use alloy::primitives::U256;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_swap1() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        let val1 = z3::ast::BV::from_u64(&ctx, 10, 256);
        let val2 = z3::ast::BV::from_u64(&ctx, 20, 256);

        machine.sym_stack.push(val1);
        machine.sym_stack.push(val2);

        // Stack: [10, 20] (Top: 20 at index 1, Base 10 at index 0)
        // stack.len() = 2.
        // SWAP1 (0x90). Offset = 1.
        // Swap(len-1, len-1-1) -> Swap(1, 0).

        handle_stack(&mut machine, 0x90);

        // Expected: [20, 10] (Top: 10 at index 1)
        let top = machine.sym_stack.peek(0);
        let top_val = u256_from_bv(&top).unwrap();
        assert_eq!(top_val, U256::from(10));

        let sec = machine.sym_stack.peek(1);
        let sec_val = u256_from_bv(&sec).unwrap();
        assert_eq!(sec_val, U256::from(20));
    }

    #[test]
    fn test_dup1() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        let val1 = z3::ast::BV::from_u64(&ctx, 10, 256);
        machine.sym_stack.push(val1);

        handle_stack(&mut machine, 0x80); // DUP1

        assert_eq!(machine.sym_stack.len(), 2);
        let top = machine.sym_stack.peek(0);
        let top_val = u256_from_bv(&top).unwrap();
        assert_eq!(top_val, U256::from(10));
    }

    #[test]
    fn test_swap_underflow() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        let val1 = z3::ast::BV::from_u64(&ctx, 1, 256);
        machine.sym_stack.push(val1);

        handle_stack(&mut machine, 0x90);
        assert!(machine.reverted);
    }
}
