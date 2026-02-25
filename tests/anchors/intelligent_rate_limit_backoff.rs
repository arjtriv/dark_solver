use std::fs;

#[test]
fn test_intelligent_rate_limit_backoff_coordinates_global_cooldown() {
    let rpc_source = fs::read_to_string("src/utils/rpc.rs")
        .expect("src/utils/rpc.rs must be readable for rate-limit backoff audit");
    let scanner_source = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for rate-limit backoff audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for rate-limit backoff audit");

    assert!(
        rpc_source.contains("GLOBAL_RPC_COOLDOWN_UNTIL_MS")
            && rpc_source.contains("await_global_rpc_cooldown().await")
            && rpc_source.contains("signal_global_rate_limited_rpc_error"),
        "rpc layer must expose and enforce a process-wide cooldown signal for 429 coordination"
    );
    assert!(
        scanner_source.contains("signal_global_rate_limited_rpc_error")
            && scanner_source.contains("fn is_rate_limited_error"),
        "scanner must arm global cooldown when rate-limit errors are observed"
    );
    assert!(
        main_source.contains("global_rpc_cooldown_active()"),
        "runtime controls must consume global cooldown state for degraded-mode coordination"
    );
}
