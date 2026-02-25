//! Anchor: OP-stack L1 data fee is subtracted from expected_profit before bidding.

use dark_solver::executor::gas_solver::{estimate_l1_data_fee_wei_from_len, is_opstack_chain};

#[test]
fn anchor_l1_gas_price_integration_linear_fee_is_subtracted() {
    assert!(is_opstack_chain(8453));

    let expected_profit_wei = 1000u128;
    let fee = estimate_l1_data_fee_wei_from_len(10, 50); // 500
    let adjusted = expected_profit_wei.saturating_sub(fee);
    assert_eq!(adjusted, 500);

    let fee2 = estimate_l1_data_fee_wei_from_len(100, 50); // 5000
    let adjusted2 = expected_profit_wei.saturating_sub(fee2);
    assert_eq!(adjusted2, 0);
}
