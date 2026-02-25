use alloy::primitives::keccak256;
use revm::primitives::Bytes;
use z3::ast::{Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn known_fee_sensitive_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("deposit(uint256)"),
        selector("deposit(uint256,address)"),
        selector("mint(uint256)"),
        selector("mint(uint256,address)"),
        selector("stake(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn selector_from_call_data(call_data: &Bytes) -> Option<[u8; 4]> {
    if call_data.len() < 4 {
        return None;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&call_data[..4]);
    Some(selector)
}

pub fn strict_received_shortfall<'ctx>(
    ctx: &'ctx Context,
    requested_amount: &BV<'ctx>,
    received_amount: &BV<'ctx>,
) -> Bool<'ctx> {
    let positive = requested_amount.bvugt(&BV::from_u64(ctx, 0, 256));
    let shortfall = received_amount.bvult(requested_amount);
    Bool::and(ctx, &[&positive, &shortfall])
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_fee_shortfall_predicate_sat_and_unsat() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let requested = BV::from_u64(&ctx, 100, 256);

        solver.push();
        let received_less = BV::from_u64(&ctx, 90, 256);
        solver.assert(&strict_received_shortfall(&ctx, &requested, &received_less));
        assert_eq!(solver.check(), z3::SatResult::Sat);
        solver.pop(1);

        solver.push();
        let received_equal = BV::from_u64(&ctx, 100, 256);
        solver.assert(&strict_received_shortfall(
            &ctx,
            &requested,
            &received_equal,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
        solver.pop(1);
    }
}
