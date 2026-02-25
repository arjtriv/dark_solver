use std::fs;

#[test]
fn test_scanner_hash_mode_receipt_fallback_is_pressure_aware_and_budgeted() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("SCAN_HASH_MODE_RECEIPT_FALLBACK_BUDGET_PER_BLOCK")
            && source.contains("load_hash_mode_receipt_fallback_budget_per_block"),
        "hash-mode scanner must expose per-block receipt fallback budget controls"
    );
    assert!(
        source.contains("pressure_err")
            && source.contains("Skipping receipt fallback")
            && source.contains("looks_like_provider_pressure(&raw_err)"),
        "tx_by_hash pressure-class errors must skip receipt fallback escalation"
    );
    assert!(
        source.contains("receipt_fallback_attempts")
            && source.contains("receipt_fallback_budget_per_block"),
        "receipt fallback escalations must be capped per block"
    );
}
