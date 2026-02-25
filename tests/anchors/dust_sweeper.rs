//! Anchor Test: scanner dust-liquidity gate remains active and monotonic.

#[test]
fn test_dust_sweeper_threshold_gate() {
    let threshold = dark_solver::scanner::default_dust_liquidity_threshold();
    let below = alloy::primitives::U256::from(10_000_000_000_000_000u128);
    let above = alloy::primitives::U256::from(100_000_000_000_000_000u128);

    assert!(!dark_solver::scanner::meets_dust_liquidity(
        below, threshold
    ));
    assert!(dark_solver::scanner::meets_dust_liquidity(
        threshold, threshold
    ));
    assert!(dark_solver::scanner::meets_dust_liquidity(above, threshold));
}
