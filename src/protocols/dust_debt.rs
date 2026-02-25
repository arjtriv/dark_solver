use crate::symbolic::utils::math::{extend_to_512, safe_div};
use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_dust_bad_debt_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("borrow(uint256)"),
        selector("borrow(address,uint256,uint256,uint16,address)"),
        selector("repay(uint256)"),
        selector("liquidateBorrow(address,uint256,address)"),
        selector("liquidationCall(address,address,address,uint256,bool)"),
        selector("absorb(address,address[])"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn liquidation_recovery_with_bonus<'ctx>(
    ctx: &'ctx Context,
    debt_value: &BV<'ctx>,
    liquidation_bonus_bps: u64,
) -> BV<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let bonus = extend_to_512(ctx, &BV::from_u64(ctx, 10_000 + liquidation_bonus_bps, 256));
    safe_div(&extend_to_512(ctx, debt_value).bvmul(&bonus), &scale).extract(255, 0)
}

pub fn liquidation_is_unprofitable<'ctx>(
    ctx: &'ctx Context,
    debt_value: &BV<'ctx>,
    liquidation_gas_cost: &BV<'ctx>,
    liquidation_bonus_bps: u64,
) -> Bool<'ctx> {
    let recovery = liquidation_recovery_with_bonus(ctx, debt_value, liquidation_bonus_bps);
    liquidation_gas_cost.bvugt(&recovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_liquidation_is_unprofitable_when_gas_exceeds_recovery() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let debt = BV::from_u64(&ctx, 10, 256);
        let gas = BV::from_u64(&ctx, 20, 256);

        solver.assert(&liquidation_is_unprofitable(&ctx, &debt, &gas, 500));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_liquidation_is_unprofitable_rejects_cheap_gas_path() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let debt = BV::from_u64(&ctx, 10, 256);
        let gas = BV::from_u64(&ctx, 5, 256);

        solver.assert(&liquidation_is_unprofitable(&ctx, &debt, &gas, 500));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
