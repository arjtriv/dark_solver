use dark_solver::protocols::lending::{
    e_mode_borrow_allowed, isolation_mode_borrow_allowed, supply_cap_allows_supply,
};
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[test]
fn test_lending_mode_anchor_supply_cap_enforced() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let total = BV::from_u64(&ctx, 900, 256);
    let add = BV::from_u64(&ctx, 200, 256);
    let cap = BV::from_u64(&ctx, 1000, 256);
    let allowed = supply_cap_allows_supply(&ctx, &total, &add, &cap);
    solver.assert(&allowed);
    assert_eq!(solver.check(), z3::SatResult::Unsat);
}

#[test]
fn test_lending_mode_anchor_isolation_and_emode_gate() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let iso_allowed = isolation_mode_borrow_allowed(
        &ctx,
        &z3::ast::Bool::from_bool(&ctx, true),
        &z3::ast::Bool::from_bool(&ctx, true),
        &BV::from_u64(&ctx, 50, 256),
        &BV::from_u64(&ctx, 25, 256),
        &BV::from_u64(&ctx, 100, 256),
    );
    let emode_allowed = e_mode_borrow_allowed(
        &ctx,
        &z3::ast::Bool::from_bool(&ctx, true),
        &z3::ast::Bool::from_bool(&ctx, true),
        &BV::from_u64(&ctx, 1_000, 256),
        &BV::from_u64(&ctx, 100, 256),
        &BV::from_u64(&ctx, 100, 256),
        &BV::from_u64(&ctx, 9500, 256),
        &BV::from_u64(&ctx, 10000, 256),
    );
    solver.assert(&iso_allowed);
    solver.assert(&emode_allowed);
    assert_eq!(solver.check(), z3::SatResult::Sat);
}
