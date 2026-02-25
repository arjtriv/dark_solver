use crate::symbolic::utils::math::{extend_to_512, safe_div};
use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_redemption_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("redeem(uint256)"),
        selector("redeem(uint256,address,address)"),
        selector("redeemUnderlying(uint256)"),
        selector("sell(uint256)"),
        selector("buy(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn value_from_bps_price<'ctx>(
    ctx: &'ctx Context,
    units: &BV<'ctx>,
    price_bps: &BV<'ctx>,
) -> BV<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    safe_div(
        &extend_to_512(ctx, units).bvmul(&extend_to_512(ctx, price_bps)),
        &scale,
    )
    .extract(255, 0)
}

pub fn redemption_arb_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    market_cost: &BV<'ctx>,
    redemption_out: &BV<'ctx>,
    min_gain_bps: u64,
) -> Bool<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let threshold = extend_to_512(
        ctx,
        &BV::from_u64(ctx, 10_000u64.saturating_add(min_gain_bps), 256),
    );
    let cost_512 = extend_to_512(ctx, market_cost);
    let out_512 = extend_to_512(ctx, redemption_out);
    out_512.bvmul(&scale).bvugt(&cost_512.bvmul(&threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_redemption_arb_exceeds_bps_accepts_positive_spread() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let market_cost = BV::from_u64(&ctx, 980, 256);
        let redemption_out = BV::from_u64(&ctx, 995, 256);

        solver.assert(&redemption_arb_exceeds_bps(
            &ctx,
            &market_cost,
            &redemption_out,
            100,
        ));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_redemption_arb_exceeds_bps_rejects_small_spread() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let market_cost = BV::from_u64(&ctx, 980, 256);
        let redemption_out = BV::from_u64(&ctx, 985, 256);

        solver.assert(&redemption_arb_exceeds_bps(
            &ctx,
            &market_cost,
            &redemption_out,
            100,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
