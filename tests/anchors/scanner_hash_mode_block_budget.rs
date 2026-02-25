use std::fs;

#[test]
fn test_scanner_hash_mode_block_budget_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("SCAN_HASH_MODE_BLOCK_BUDGET_MS"),
        "Scanner must expose hash-mode per-block budget env control."
    );
    assert!(
        source.contains("Hash-mode block budget exhausted at block"),
        "Hash-mode ingestion must emit budget exhaustion signal."
    );
    assert!(
        source.contains("now_ms().saturating_sub(block_started_ms) >= block_budget_ms"),
        "Hash-mode ingestion must enforce deadline checks during tx/dust loops."
    );
}
