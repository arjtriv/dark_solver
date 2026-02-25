use std::fs;

#[test]
fn test_scanner_and_forkdb_fail_closed_guards_are_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");
    let fork_db = fs::read_to_string("src/fork_db.rs").expect("src/fork_db.rs must be readable");

    assert!(
        scanner.contains("SCAN_CHAIN_ID_TIMEOUT_MS")
            && scanner.contains("Timed out fetching chain id")
            && scanner.contains("Failed to fetch reconnect head"),
        "scanner startup must fail closed on chain-id/head bootstrap uncertainty"
    );
    assert!(
        scanner.contains("SCAN_HASH_MODE_TX_FETCH_TIMEOUT_MS")
            && scanner.contains("tx hydration timed out")
            && scanner.contains("SCAN_HASH_MODE_RECEIPT_FETCH_TIMEOUT_MS"),
        "hash-mode hydration must enforce bounded tx/receipt fetch windows"
    );
    assert!(
        scanner.contains("SCAN_BLOCK_WORKER_CONCURRENCY") && scanner.contains("OPSTACK_CHAIN_IDS"),
        "scanner should expose worker/opstack chain controls via configuration"
    );

    assert!(
        fork_db.contains("nonce == 0 && r_balance.is_zero() && code.is_empty()")
            && fork_db.contains("return Ok(None);"),
        "ForkDB basic_ref must preserve non-existent account semantics"
    );
    assert!(
        fork_db.contains("reference_head.saturating_sub(number) > 256")
            && fork_db.contains("B256::ZERO"),
        "ForkDB block_hash_ref must enforce EVM 256-block window semantics"
    );
    assert!(
        fork_db.contains("missing bytecode for code hash")
            && fork_db.contains("FORKDB_BRIDGE_TIMEOUT_MS")
            && fork_db.contains("recv_timeout"),
        "ForkDB must fail closed on missing code-hash lookups and bounded bridge waits"
    );
}
