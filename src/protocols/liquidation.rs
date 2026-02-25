use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_liquidation_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("liquidate(address,uint256,address)"),
        selector("liquidateBorrow(address,uint256,address)"),
        selector("liquidationCall(address,address,address,uint256,bool)"),
        selector("liquidate(address,address,uint256,uint256)"),
        selector("absorb(address,address[])"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn reserve_drop<'ctx>(
    _ctx: &'ctx Context,
    reserve_before: &BV<'ctx>,
    reserve_after: &BV<'ctx>,
) -> Bool<'ctx> {
    reserve_after.bvult(reserve_before)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_reserve_drop_accepts_strict_depletion() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let before = BV::from_u64(&ctx, 200, 256);
        let after = BV::from_u64(&ctx, 150, 256);
        solver.assert(&reserve_drop(&ctx, &before, &after));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_reserve_drop_rejects_non_decreasing_state() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let before = BV::from_u64(&ctx, 200, 256);
        let after = BV::from_u64(&ctx, 200, 256);
        solver.assert(&reserve_drop(&ctx, &before, &after));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
