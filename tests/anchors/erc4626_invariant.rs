use dark_solver::protocols::erc4626::assets_per_share_non_decreasing;
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[test]
fn test_erc4626_anchor_detects_ratio_regression() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let init_assets = BV::from_u64(&ctx, 1_000, 256);
    let init_supply = BV::from_u64(&ctx, 1_000, 256);
    let final_assets = BV::from_u64(&ctx, 900, 256);
    let final_supply = BV::from_u64(&ctx, 1_000, 256);

    let inv = assets_per_share_non_decreasing(
        &ctx,
        &init_assets,
        &init_supply,
        &final_assets,
        &final_supply,
    );
    solver.assert(&inv.not());
    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn test_erc4626_anchor_accepts_ratio_improvement() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let init_assets = BV::from_u64(&ctx, 1_000, 256);
    let init_supply = BV::from_u64(&ctx, 1_000, 256);
    let final_assets = BV::from_u64(&ctx, 1_100, 256);
    let final_supply = BV::from_u64(&ctx, 1_000, 256);

    let inv = assets_per_share_non_decreasing(
        &ctx,
        &init_assets,
        &init_supply,
        &final_assets,
        &final_supply,
    );
    solver.assert(&inv.not());
    assert_eq!(solver.check(), z3::SatResult::Unsat);
}
