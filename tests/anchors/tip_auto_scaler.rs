//! Anchor: Tip auto-scaler outbids contested competition by `p75 + 1 wei` when profitable.

use alloy::primitives::Address;
use dark_solver::executor::gas_solver::GasOptimalitySolver;
use dark_solver::executor::tip_auto_scaler::ContestedTipCache;

#[test]
fn tip_auto_scaler_raises_tip_to_p75_plus_one_when_contested_and_budget_allows() {
    let solver = GasOptimalitySolver::new(
        1_000_000_000, // 1 gwei base
        vec![
            100_000_000,   // p10
            200_000_000,   // p25
            500_000_000,   // p50
            1_000_000_000, // p75
            2_000_000_000, // p90
        ],
    );
    let profit = 10_000_000_000_000_000_000u128; // 10 ETH
    let gas = 200_000u64;
    let tip = solver.optimal_tip_auto_scaled(profit, gas, true);
    assert_eq!(tip, 1_000_000_000u128 + 1);
}

#[test]
fn tip_auto_scaler_does_not_raise_tip_when_not_contested() {
    let solver = GasOptimalitySolver::new(1_000_000_000, vec![100, 200, 500, 1_000, 2_000]);
    let profit = 10_000_000_000_000_000_000u128;
    let gas = 200_000u64;
    let base = solver.optimal_tip_auto_scaled(profit, gas, false);
    assert_eq!(base, solver.optimal_tip(profit, gas));
}

#[test]
fn contested_tip_cache_expires_after_ttl_blocks() {
    let mut cache = ContestedTipCache::new(2);
    let target = Address::repeat_byte(0x11);
    cache.mark_contested(target, 100);
    assert!(cache.is_contested(target, 101));
    assert!(cache.is_contested(target, 102));
    assert!(!cache.is_contested(target, 103));
}
