//! Anchor Test: targeted reentrancy branch pruning.

use dark_solver::symbolic::state::SymbolicMachine;
use z3::{ast::BV, Config, Context, Solver};

#[test]
fn test_reentrancy_branch_prunes_without_invariant_touch() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let modeled_reentry = machine.fork_reentrancy_branch(42);
    assert!(modeled_reentry);
    assert!(machine.should_prune_reentrancy_path());

    let non_invariant_slot = BV::new_const(&ctx, "anchor_non_invariant_slot", 256);
    machine.mark_reentrancy_sstore(&non_invariant_slot);

    assert!(machine.should_prune_reentrancy_path());
    assert!(!machine.reentrancy_detected);
}

#[test]
fn test_reentrancy_branch_keeps_invariant_touch() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let modeled_reentry = machine.fork_reentrancy_branch(7);
    assert!(modeled_reentry);

    // Slot 8 is treated as reserve-like state (K-constraint critical).
    let invariant_slot = BV::from_u64(&ctx, 8, 256);
    machine.mark_reentrancy_sstore(&invariant_slot);

    assert!(!machine.should_prune_reentrancy_path());
    assert!(machine.reentrancy_detected);
}
