use std::fs;

#[test]
fn test_multicall3_balance_batch_hydration_is_present_in_scanner_and_setup() {
    let setup = fs::read_to_string("src/solver/setup.rs")
        .expect("src/solver/setup.rs must be readable for multicall hydration audit");
    assert!(
        setup.contains("fetch_attacker_token_balances_multicall_async"),
        "solver setup must batch attacker balanceOf calls via Multicall3"
    );
    assert!(
        setup.contains("aggregate3"),
        "solver setup must define Multicall3 aggregate3 ABI"
    );

    let scanner = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for multicall hydration audit");
    assert!(
        scanner.contains("aggregate3"),
        "scanner must define Multicall3 aggregate3 ABI for high-value TVL gating"
    );
}
