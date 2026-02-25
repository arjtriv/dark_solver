use alloy::primitives::U256;

#[test]
fn test_flash_loan_profit_check() {
    // 1. Setup
    let initial_balance = U256::from(1_500_000_000_000_000_000u64); // 1.5 ETH
    let loan_amount = U256::from(100_000_000_000_000_000_000u128); // 100 ETH

    // Scenario A: We kept the loan (Cheat/Fail)
    let final_bal_fail = initial_balance + loan_amount + U256::from(100); // +100 profit but loan kept

    let is_profitable_fail = if final_bal_fail > (initial_balance + loan_amount) {
        println!("FAIL: High balance (Loan not repaid)");
        false
    } else {
        true
    };
    assert!(!is_profitable_fail, "Should flag loan hoarding as failure");

    // Scenario B: We repaid loan + fee + profit
    let _fee = loan_amount / U256::from(1000); // 0.1 ETH
    let profit = U256::from(500_000_000_000_000_000u64); // 0.5 ETH

    // If we repaid, our balance is Initial + Profit - Fee (assuming we paid fee from profit)
    // Actually, normally:
    // Start: 1.5
    // Borrow: 101.5
    // Exploit: 104.5 (Made 3 ETH)
    // Repay: 4.4 (Sent 100.1 back)
    // End: 4.4

    let final_bal_success = initial_balance + profit; // Net result after EVERYTHING

    let is_profitable_success = final_bal_success > initial_balance;

    assert!(is_profitable_success, "Should pass valid profit check");
}
