use alloy::primitives::Address;
use dark_solver::executor::verifier::{is_profitable, TokenBalanceDelta};
use revm::primitives::U256;

#[test]
fn test_shadow_verifier_profit_gate_accepts_token_gain() {
    let deltas = vec![TokenBalanceDelta {
        token: Address::from([0x44; 20]),
        initial: U256::from(100u64),
        final_balance: U256::from(101u64),
    }];

    let profitable = is_profitable(U256::from(10u64), U256::from(10u64), &deltas);
    assert!(profitable);
}

#[test]
fn test_shadow_verifier_profit_gate_rejects_no_gain() {
    let deltas = vec![TokenBalanceDelta {
        token: Address::from([0x55; 20]),
        initial: U256::from(77u64),
        final_balance: U256::from(77u64),
    }];

    let profitable = is_profitable(U256::from(20u64), U256::from(20u64), &deltas);
    assert!(!profitable);
}
