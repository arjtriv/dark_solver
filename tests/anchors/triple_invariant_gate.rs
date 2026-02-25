//! Anchor Test: Global Triple Invariant Gate (Solvency + Price Sanity + K-Constraint)

use std::collections::HashMap;

use dark_solver::solver::invariants::GlobalInvariantChecker;
use dark_solver::solver::setup::ATTACKER;
use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::configure_solver;
use revm::primitives::Address;
use z3::ast::BV;
use z3::{Config, Context, SatResult, Solver};

#[test]
fn test_triple_gate_anchor_unsat_on_k_drop() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let pair = Address::from([0x31; 20]);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 20_000, 256));
    machine.manipulated_reserves.insert(
        pair,
        (BV::from_u64(&ctx, 1_200, 256), BV::from_u64(&ctx, 100, 256)),
    );

    let mut baseline = HashMap::new();
    baseline.insert(
        pair,
        (
            BV::from_u64(&ctx, 1_000, 256),
            BV::from_u64(&ctx, 1_000, 256),
        ),
    );

    let checker = GlobalInvariantChecker::default();
    let loan = BV::from_u64(&ctx, 100, 256);
    let gate = checker.build_constraints_with_baselines(&ctx, &machine, ATTACKER, &loan, &baseline);
    solver.assert(&gate);
    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn test_triple_gate_anchor_sat_on_solvent_k_safe_path() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let pair = Address::from([0x32; 20]);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 20_000, 256));
    machine.manipulated_reserves.insert(
        pair,
        (BV::from_u64(&ctx, 1_050, 256), BV::from_u64(&ctx, 980, 256)),
    );

    let mut baseline = HashMap::new();
    baseline.insert(
        pair,
        (
            BV::from_u64(&ctx, 1_000, 256),
            BV::from_u64(&ctx, 1_000, 256),
        ),
    );

    let checker = GlobalInvariantChecker::default();
    let loan = BV::from_u64(&ctx, 100, 256);
    let gate = checker.build_constraints_with_baselines(&ctx, &machine, ATTACKER, &loan, &baseline);
    solver.assert(&gate);
    assert_eq!(solver.check(), SatResult::Sat);
}
