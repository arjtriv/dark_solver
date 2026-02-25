use crate::symbolic::utils::math::{extend_to_512, safe_div, wad};
use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_interest_rate_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("deposit(uint256)"),
        selector("withdraw(uint256)"),
        selector("borrow(uint256)"),
        selector("repay(uint256)"),
        selector("supply(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn utilization_wad<'ctx>(
    ctx: &'ctx Context,
    total_borrows: &BV<'ctx>,
    total_supply: &BV<'ctx>,
) -> BV<'ctx> {
    let borrows_512 = extend_to_512(ctx, total_borrows);
    let supply_512 = extend_to_512(ctx, total_supply);
    let wad_512 = extend_to_512(ctx, &wad(ctx));
    safe_div(&borrows_512.bvmul(&wad_512), &supply_512).extract(255, 0)
}

pub fn linear_borrow_rate_wad<'ctx>(
    ctx: &'ctx Context,
    base_rate: &BV<'ctx>,
    slope: &BV<'ctx>,
    utilization: &BV<'ctx>,
) -> BV<'ctx> {
    let base_512 = extend_to_512(ctx, base_rate);
    let slope_512 = extend_to_512(ctx, slope);
    let util_512 = extend_to_512(ctx, utilization);
    let wad_512 = extend_to_512(ctx, &wad(ctx));
    let variable = safe_div(&slope_512.bvmul(&util_512), &wad_512);
    base_512.bvadd(&variable).extract(255, 0)
}

pub fn rate_drop_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    rate_before: &BV<'ctx>,
    rate_after: &BV<'ctx>,
    min_drop_bps: u64,
) -> Bool<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let threshold = extend_to_512(
        ctx,
        &BV::from_u64(ctx, 10_000u64.saturating_sub(min_drop_bps), 256),
    );
    let before_512 = extend_to_512(ctx, rate_before);
    let after_512 = extend_to_512(ctx, rate_after);
    after_512.bvmul(&scale).bvult(&before_512.bvmul(&threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_rate_drop_exceeds_bps_detects_crash() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let before = BV::from_u64(&ctx, 1_000_000_000_000_000_000, 256);
        let after = BV::from_u64(&ctx, 300_000_000_000_000_000, 256);

        solver.assert(&rate_drop_exceeds_bps(&ctx, &before, &after, 5000));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_rate_drop_exceeds_bps_rejects_small_move() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let before = BV::from_u64(&ctx, 1_000, 256);
        let after = BV::from_u64(&ctx, 950, 256);

        solver.assert(&rate_drop_exceeds_bps(&ctx, &before, &after, 1000));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
