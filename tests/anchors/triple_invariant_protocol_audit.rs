//! Anchor Test: protocol models must remain gated by Triple Invariants.

use std::collections::HashMap;

use dark_solver::protocols::{curve, lending, uniswap_v2};
use dark_solver::solver::invariants::GlobalInvariantChecker;
use dark_solver::solver::setup::ATTACKER;
use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::utils::math::extend_to_512;
use dark_solver::symbolic::z3_ext::configure_solver;
use revm::primitives::Address;
use z3::ast::BV;
use z3::{Config, Context, SatResult, Solver};

#[test]
fn test_univ2_model_remains_sat_under_triple_gate() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let pair = Address::from([0x41; 20]);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 20_000, 256));

    let reserve_in = BV::from_u64(&ctx, 1_000, 256);
    let reserve_out = BV::from_u64(&ctx, 1_000, 256);
    let amount_in = BV::from_u64(&ctx, 100, 256);
    let amount_out = uniswap_v2::get_amount_out(&amount_in, &reserve_in, &reserve_out);

    let r0_after = reserve_in.bvadd(&amount_in);
    let r1_after = reserve_out.bvsub(&amount_out);
    solver.assert(&r0_after.bvuge(&reserve_in));
    solver.assert(&amount_out.bvule(&reserve_out));

    machine
        .manipulated_reserves
        .insert(pair, (r0_after, r1_after));

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

#[test]
fn test_curve_model_forced_k_drop_is_blocked_by_triple_gate() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let pair = Address::from([0x42; 20]);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 20_000, 256));

    // Use a deterministic, known-valid Curve state to keep the proof bounded.
    let amp = BV::from_u64(&ctx, 100, 256);
    let d = BV::from_u64(&ctx, 2_000, 256);
    let balanced_x = BV::from_u64(&ctx, 1_000, 256);
    let balanced_y = BV::from_u64(&ctx, 1_000, 256);
    solver.assert(&curve::is_invariant_satisfied(
        &ctx,
        &balanced_x,
        &balanced_y,
        &amp,
        &d,
    ));

    let x = BV::from_u64(&ctx, 1_200, 256);
    let y = BV::from_u64(&ctx, 100, 256);

    let k_before = extend_to_512(&ctx, &BV::from_u64(&ctx, 1_000, 256))
        .bvmul(&extend_to_512(&ctx, &BV::from_u64(&ctx, 1_000, 256)));
    let k_after = extend_to_512(&ctx, &x).bvmul(&extend_to_512(&ctx, &y));
    solver.assert(&k_after.bvult(&k_before));

    machine.manipulated_reserves.insert(pair, (x, y));

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
fn test_lending_insolvency_implies_triple_gate_unsat() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let collateral_value = BV::from_u64(&ctx, 900, 256);
    let debt_value = BV::from_u64(&ctx, 1_000, 256);
    solver.assert(&lending::is_insolvent(&ctx, &collateral_value, &debt_value));

    let machine = {
        let mut m = SymbolicMachine::new(&ctx, &solver, None);
        m.inject_balance_override(ATTACKER, collateral_value);
        m
    };

    let checker = GlobalInvariantChecker::default();
    let gate = checker.build_constraints_with_baselines(
        &ctx,
        &machine,
        ATTACKER,
        &debt_value,
        &HashMap::new(),
    );
    solver.assert(&gate);
    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn test_lending_solvent_path_keeps_triple_gate_sat() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let collateral_value = BV::from_u64(&ctx, 2_000, 256);
    let debt_value = BV::from_u64(&ctx, 900, 256);
    solver.assert(&lending::is_insolvent(&ctx, &collateral_value, &debt_value).not());

    let threshold = BV::from_u64(&ctx, 8_000, 256);
    let precision = BV::from_u64(&ctx, 10_000, 256);
    solver.assert(
        &lending::is_liquidatable(&ctx, &collateral_value, &debt_value, &threshold, &precision)
            .not(),
    );

    let machine = {
        let mut m = SymbolicMachine::new(&ctx, &solver, None);
        m.inject_balance_override(ATTACKER, collateral_value);
        m
    };

    let checker = GlobalInvariantChecker::default();
    let gate = checker.build_constraints_with_baselines(
        &ctx,
        &machine,
        ATTACKER,
        &debt_value,
        &HashMap::new(),
    );
    solver.assert(&gate);
    assert_eq!(solver.check(), SatResult::Sat);
}
