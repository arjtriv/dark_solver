//! Anchor Test: fee-on-transfer shortfall predicate and selector model stay stable.

#[test]
fn test_fee_on_transfer_anchor_shortfall_and_selector_model() {
    let selectors = dark_solver::protocols::fee_on_transfer::known_fee_sensitive_selectors();
    assert!(
        !selectors.is_empty(),
        "fee-sensitive selector catalog must not be empty"
    );

    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);
    let solver = z3::Solver::new(&ctx);

    solver.push();
    let requested = z3::ast::BV::from_u64(&ctx, 100, 256);
    let received = z3::ast::BV::from_u64(&ctx, 97, 256);
    let shortfall = dark_solver::protocols::fee_on_transfer::strict_received_shortfall(
        &ctx, &requested, &received,
    );
    solver.assert(&shortfall);
    assert_eq!(solver.check(), z3::SatResult::Sat);
    solver.pop(1);

    solver.push();
    let equal_received = z3::ast::BV::from_u64(&ctx, 100, 256);
    let no_shortfall = dark_solver::protocols::fee_on_transfer::strict_received_shortfall(
        &ctx,
        &requested,
        &equal_received,
    );
    solver.assert(&no_shortfall);
    assert_eq!(solver.check(), z3::SatResult::Unsat);
    solver.pop(1);
}
