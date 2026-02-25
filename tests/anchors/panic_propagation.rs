//! Anchor: symbolic stack underflow must fail closed without panicking.

use alloy::primitives::U256;
use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::u256_from_bv;
use z3::{Config, Context, Solver};

#[test]
fn test_symbolic_stack_underflow_sets_flag_and_returns_zero() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // Underflow on empty stack should not panic; it should set an explicit flag so the engine can
    // mark the path as reverted (InstructionResult::StackUnderflow).
    let popped = machine.sym_stack.pop();
    assert!(machine.sym_stack.take_underflowed());
    assert_eq!(u256_from_bv(&popped), Some(U256::ZERO));
}
