use std::fs;

#[test]
fn test_scanner_executor_ingest_probe_budget_hardening_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");
    let executor =
        fs::read_to_string("src/executor/mod.rs").expect("src/executor/mod.rs must be readable");

    assert!(
        scanner.contains("SCAN_HIGH_VALUE_PROBES_PER_BLOCK")
            && scanner.contains("SCAN_HIGH_VALUE_DEPLOYMENT_PROBES_PER_BLOCK")
            && scanner.contains("HighValueProbeBudget")
            && scanner.contains("address_passes_high_value_gate(")
            && scanner.contains("target_capital_estimate_eth_wei(address)")
            && scanner.contains("reserve_deployment_probe()"),
        "scanner hash/full ingest must enforce cache-first high-value probe budgets, including bounded deployment probes"
    );

    assert!(
        scanner.contains("drop(permit);") && scanner.contains("ingest_tx_target("),
        "hash-mode fallback permits must be released before multi-RPC ingest logic"
    );

    assert!(
        scanner.contains("provider.get_balance(address)")
            && scanner.contains("Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS)"),
        "dust-liquidity balance checks must be time-bounded fail-closed"
    );

    assert!(
        executor.contains("get_block_number_with_retry_ref(&self.provider, 2)")
            && !executor.contains(
                "RobustRpc::get_block_number_with_retry(Arc::new(self.provider.clone()), 2)"
            ),
        "executor head fetch must use ref-based retry without per-fetch Arc allocation"
    );
}
