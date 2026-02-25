use alloy::primitives::{Address, B256, U256};
use dark_solver::solver::objectives::{ExploitObjective, ExploitParams, GenericProfitObjective};

#[tokio::test]
async fn test_api_surface_integrity() {
    // Compile-time integrity check for the public solver objective API surface.

    // 1. Verify ExploitParams Structure
    let _params = ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: vec![dark_solver::solver::objectives::ExploitStep {
            target: Address::ZERO,
            call_data: alloy::primitives::Bytes::new(),
            execute_if: None,
        }],
        expected_profit: Some(U256::ZERO),
        block_offsets: None,
    };

    // 2. Verify Objective Interface
    let obj = GenericProfitObjective {
        rpc_url: "http://localhost:8545".to_string(),
        chain_id: 1,
    };
    assert_eq!(obj.name(), "Generic Invariant Breach (Loan-Financed Path)");
}

#[test]
fn test_primitive_conversions() {
    // Guard the Alloy/REVM bridge conversions used across the codebase.
    let val = U256::from(1);
    let _fixed: [u8; 32] = val.to_be_bytes();
    let _addr = Address::from_word(B256::from(val));
}
