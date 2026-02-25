use dark_solver::protocols::{curve, lending};
use dark_solver::symbolic::utils::math::val;
use z3::Config;
use z3::Context;

#[test]
fn test_curve_invariant() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    // Setup typical StableSwap (USD-like)
    // A = 100
    // x = 1000
    // y = 1000
    // D should be 2000 if perfectly balanced.

    let a = val(&ctx, 100);
    let x = val(&ctx, 1000);
    let y = val(&ctx, 1000);
    let d = val(&ctx, 2000); // 1000 + 1000 = 2000

    let is_sat = curve::is_invariant_satisfied(&ctx, &x, &y, &a, &d);

    let solver = z3::Solver::new(&ctx);
    solver.assert(&is_sat);
    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn test_lending_bad_debt() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    // Collateral = 1000 ETH @ $2000 = $2,000,000
    // Debt = 2,000,001 USDC @ $1 = $2,000,001
    // Should be Bad Debt

    let col_val = val(&ctx, 2_000_000);
    let debt_val = val(&ctx, 2_000_001);

    let is_bad = lending::is_insolvent(&ctx, &col_val, &debt_val);

    let solver = z3::Solver::new(&ctx);
    solver.assert(&is_bad);
    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn test_lending_liquidation() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    // Collateral = $1000
    // Debt = $850
    // Threshold = 80% (8000 BPS)
    // Max Borrow = 800.
    // Debt > Max Borrow. Should be liquidatable.

    let col_val = val(&ctx, 1000);
    let debt_val = val(&ctx, 850);
    let threshold = val(&ctx, 8000);
    let precision = val(&ctx, 10000);

    let is_liq = lending::is_liquidatable(&ctx, &col_val, &debt_val, &threshold, &precision);

    let solver = z3::Solver::new(&ctx);
    solver.assert(&is_liq);
    assert_eq!(solver.check(), z3::SatResult::Sat);
}
