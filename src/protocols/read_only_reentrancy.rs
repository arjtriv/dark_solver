use crate::symbolic::utils::math::{extend_to_512, zero};
use revm::primitives::Bytes;
use z3::ast::{Ast, Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

fn bytecode_contains_selector(bytecode: &Bytes, selector: [u8; 4]) -> bool {
    let bytes = bytecode.as_ref();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 && bytes[i + 1..i + 5] == selector {
            return true;
        }
    }
    false
}

pub fn known_read_only_reentrancy_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("get_virtual_price()"),
        selector("remove_liquidity_one_coin(uint256,int128,uint256)"),
        selector("remove_liquidity(uint256,uint256[])"),
        selector("swap(uint256,uint256,uint256,uint256)"),
        selector("mint(uint256)"),
        selector("borrow(uint256)"),
        selector("liquidate(address,uint256,address)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_read_only_reentrancy_scanner_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("get_virtual_price()"),
        selector("latestAnswer()"),
        selector("mint(uint256)"),
        selector("borrow(uint256)"),
        selector("liquidate(address,uint256,address)"),
        selector("remove_liquidity_one_coin(uint256,int128,uint256)"),
        selector("remove_liquidity(uint256,uint256[])"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_read_only_reentrancy_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_staticcall = bytes.contains(&0xfa); // STATICCALL
    let has_call = bytes.contains(&0xf1); // CALL (callback edge)
    let has_view_selector = bytecode_contains_selector(bytecode, selector("get_virtual_price()"));
    let has_callback_source =
        bytecode_contains_selector(
            bytecode,
            selector("remove_liquidity_one_coin(uint256,int128,uint256)"),
        ) || bytecode_contains_selector(bytecode, selector("remove_liquidity(uint256,uint256[])"))
            || bytecode_contains_selector(
                bytecode,
                selector("swap(uint256,uint256,uint256,uint256)"),
            );
    let has_consumer_selector = bytecode_contains_selector(bytecode, selector("mint(uint256)"))
        || bytecode_contains_selector(bytecode, selector("borrow(uint256)"))
        || bytecode_contains_selector(bytecode, selector("liquidate(address,uint256,address)"));

    has_staticcall && has_call && has_view_selector && has_callback_source && has_consumer_selector
}

pub fn has_read_only_reentrancy_scanner_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_staticcall = bytes.contains(&0xfa); // STATICCALL
    let has_consumer_selector = bytecode_contains_selector(bytecode, selector("mint(uint256)"))
        || bytecode_contains_selector(bytecode, selector("borrow(uint256)"))
        || bytecode_contains_selector(bytecode, selector("liquidate(address,uint256,address)"));
    let has_callback_source =
        bytecode_contains_selector(
            bytecode,
            selector("remove_liquidity_one_coin(uint256,int128,uint256)"),
        ) || bytecode_contains_selector(bytecode, selector("remove_liquidity(uint256,uint256[])"))
            || bytecode_contains_selector(
                bytecode,
                selector("swap(uint256,uint256,uint256,uint256)"),
            );

    has_staticcall && has_consumer_selector && has_callback_source
}

pub fn stale_view_price_drift_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    mid_price: &BV<'ctx>,
    post_price: &BV<'ctx>,
    min_drift_bps: u64,
) -> Bool<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let drift = extend_to_512(ctx, &BV::from_u64(ctx, min_drift_bps, 256));
    let zero_512 = extend_to_512(ctx, &zero(ctx));

    let lhs = extend_to_512(ctx, mid_price).bvmul(&scale);
    let rhs = extend_to_512(ctx, post_price).bvmul(&extend_to_512(
        ctx,
        &BV::from_u64(ctx, 10_000 + min_drift_bps, 256),
    ));

    Bool::and(
        ctx,
        &[
            &mid_price.bvugt(&zero(ctx)),
            &post_price.bvugt(&zero(ctx)),
            &mid_price._eq(post_price).not(),
            &drift.bvugt(&zero_512),
            &lhs.bvugt(&rhs),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_has_read_only_reentrancy_pattern_detects_staticcall_callback_and_consumer_surface() {
        let view = selector("get_virtual_price()");
        let callback = selector("remove_liquidity_one_coin(uint256,int128,uint256)");
        let consumer = selector("borrow(uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&view);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&callback);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&consumer);
        bytecode.extend_from_slice(&[0xfa, 0xf1, 0x00]); // STATICCALL + CALL
        assert!(has_read_only_reentrancy_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_stale_view_price_drift_exceeds_bps_rejects_equal_prices() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mid_price = BV::from_u64(&ctx, 1000, 256);
        let post_price = BV::from_u64(&ctx, 1000, 256);

        solver.assert(&stale_view_price_drift_exceeds_bps(
            &ctx,
            &mid_price,
            &post_price,
            50,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_has_read_only_reentrancy_scanner_pattern_detects_staticcall_consumer_and_callback() {
        let consumer = selector("borrow(uint256)");
        let callback = selector("remove_liquidity_one_coin(uint256,int128,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&consumer);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&callback);
        bytecode.extend_from_slice(&[0xfa, 0x00]); // STATICCALL
        assert!(has_read_only_reentrancy_scanner_pattern(&Bytes::from(
            bytecode
        )));
    }
}
