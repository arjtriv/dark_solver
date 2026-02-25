//! Anchor: high-capital targets ignore generic RPC cooldown fail-close.

use alloy::primitives::{Address, U256};
use dark_solver::executor::execution_policy::should_override_rpc_cooldown_for_high_capital;
use dark_solver::scanner::{record_target_capital_estimate, target_capital_estimate_eth_wei};

#[test]
fn anchor_pressure_optimized_risk_weighting_uses_capital_estimate() {
    let target = Address::from([0x11; 20]);
    record_target_capital_estimate(target, U256::from(123u64));
    assert_eq!(
        target_capital_estimate_eth_wei(target),
        Some(U256::from(123u64))
    );

    assert!(!should_override_rpc_cooldown_for_high_capital(
        true,
        target_capital_estimate_eth_wei(target),
        U256::from(124u64)
    ));
    assert!(should_override_rpc_cooldown_for_high_capital(
        true,
        target_capital_estimate_eth_wei(target),
        U256::from(123u64)
    ));
}
