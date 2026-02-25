use dark_solver::symbolic::state::SymbolicMachine;
use z3::{ast::BV, Config, Context, Solver};

#[test]
fn test_reentrancy_branch_prunes_without_invariant_touch() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let modeled_reentry = machine.fork_reentrancy_branch(42);
    assert!(
        modeled_reentry,
        "expected default branch to model attacker callback"
    );
    assert!(machine.should_prune_reentrancy_path());

    let non_invariant_slot = BV::new_const(&ctx, "non_invariant_slot", 256);
    machine.mark_reentrancy_sstore(&non_invariant_slot);

    assert!(
        machine.should_prune_reentrancy_path(),
        "branch without invariant-state touch should stay pruned"
    );
    assert!(
        !machine.reentrancy_detected,
        "non-invariant writes must not be flagged as targeted reentrancy"
    );
}

#[test]
fn test_reentrancy_branch_keeps_invariant_touch() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let modeled_reentry = machine.fork_reentrancy_branch(7);
    assert!(
        modeled_reentry,
        "expected default branch to model attacker callback"
    );

    // Slot 8 is treated as reserve-like state (K-constraint critical).
    let invariant_slot = BV::from_u64(&ctx, 8, 256);
    machine.mark_reentrancy_sstore(&invariant_slot);

    assert!(
        !machine.should_prune_reentrancy_path(),
        "invariant slot touch should keep reentrancy branch explorable"
    );
    assert!(machine.reentrancy_detected);
}
