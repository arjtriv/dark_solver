use crate::symbolic::utils::math::{extend_to_512, one, safe_div, val};
use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_amm_price_impact_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
        selector(
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
        ),
        selector("liquidationCall(address,address,address,uint256,bool)"),
        selector("liquidateBorrow(address,uint256,address)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn sqrt_price_x96_after_input<'ctx>(
    ctx: &'ctx Context,
    amount_in: &BV<'ctx>,
    liquidity: &BV<'ctx>,
    sqrt_price_x96: &BV<'ctx>,
    zero_for_one: bool,
    fee_pips: u64,
) -> BV<'ctx> {
    let fee_multiplier = val(ctx, 1_000_000 - fee_pips);
    let fee_denominator = val(ctx, 1_000_000);

    let amount_rem_512 = extend_to_512(ctx, amount_in)
        .bvmul(&extend_to_512(ctx, &fee_multiplier))
        .bvudiv(&extend_to_512(ctx, &fee_denominator));
    let n96 = val(ctx, 96);
    let q96_512 = extend_to_512(ctx, &one(ctx)).bvshl(&extend_to_512(ctx, &n96));

    let liq_512 = extend_to_512(ctx, liquidity);
    let sqrtp_512 = extend_to_512(ctx, sqrt_price_x96);

    if zero_for_one {
        let numerator = liq_512.bvmul(&sqrtp_512).bvmul(&q96_512);
        let denominator = liq_512
            .bvmul(&q96_512)
            .bvadd(&amount_rem_512.bvmul(&sqrtp_512));
        safe_div(&numerator, &denominator).extract(255, 0)
    } else {
        let delta_sqrt = safe_div(&amount_rem_512.bvmul(&q96_512), &liq_512);
        sqrtp_512.bvadd(&delta_sqrt).extract(255, 0)
    }
}

pub fn sqrt_price_drop_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    sqrt_before_x96: &BV<'ctx>,
    sqrt_after_x96: &BV<'ctx>,
    min_drop_bps: u64,
) -> Bool<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let threshold = extend_to_512(
        ctx,
        &BV::from_u64(ctx, 10_000u64.saturating_sub(min_drop_bps), 256),
    );
    let before_sq = extend_to_512(ctx, sqrt_before_x96).bvmul(&extend_to_512(ctx, sqrt_before_x96));
    let after_sq = extend_to_512(ctx, sqrt_after_x96).bvmul(&extend_to_512(ctx, sqrt_after_x96));
    after_sq.bvmul(&scale).bvule(&before_sq.bvmul(&threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_sqrt_price_drop_exceeds_bps_accepts_large_drop() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let before = BV::from_u64(&ctx, 1_000_000, 256);
        let after = BV::from_u64(&ctx, 700_000, 256);
        solver.assert(&sqrt_price_drop_exceeds_bps(&ctx, &before, &after, 4_000));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_sqrt_price_drop_exceeds_bps_rejects_small_drop() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let before = BV::from_u64(&ctx, 1_000_000, 256);
        let after = BV::from_u64(&ctx, 980_000, 256);
        solver.assert(&sqrt_price_drop_exceeds_bps(&ctx, &before, &after, 1_000));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
