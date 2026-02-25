use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_psm_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("sellGem(address,uint256)"),
        selector("buyGem(address,uint256)"),
        selector("swap(uint256)"),
        selector("swapExactIn(uint256,address,address)"),
        selector("swapExactOut(uint256,address,address)"),
        selector("redeem(uint256)"),
        selector("mint(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn psm_drain_ratio_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    in_amount: &BV<'ctx>,
    out_amount: &BV<'ctx>,
    min_gain_bps: u64,
) -> Bool<'ctx> {
    let scale = crate::symbolic::utils::math::extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let threshold = crate::symbolic::utils::math::extend_to_512(
        ctx,
        &BV::from_u64(ctx, 10_000u64.saturating_add(min_gain_bps), 256),
    );
    let in_512 = crate::symbolic::utils::math::extend_to_512(ctx, in_amount);
    let out_512 = crate::symbolic::utils::math::extend_to_512(ctx, out_amount);

    out_512.bvmul(&scale).bvugt(&in_512.bvmul(&threshold))
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_psm_drain_ratio_exceeds_bps_accepts_profitable_spread() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let in_amount = BV::from_u64(&ctx, 100, 256);
        let out_amount = BV::from_u64(&ctx, 110, 256);

        solver.assert(&psm_drain_ratio_exceeds_bps(
            &ctx,
            &in_amount,
            &out_amount,
            500,
        ));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_psm_drain_ratio_exceeds_bps_rejects_below_threshold() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let in_amount = BV::from_u64(&ctx, 100, 256);
        let out_amount = BV::from_u64(&ctx, 102, 256);

        solver.assert(&psm_drain_ratio_exceeds_bps(
            &ctx,
            &in_amount,
            &out_amount,
            500,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
