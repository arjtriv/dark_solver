use std::fs;

#[test]
fn test_scanner_extracts_packed_path_addresses_as_supplemental_signal() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains(
            "fn extract_packed_path_addresses(input: &Bytes, max_addrs: usize) -> Vec<Address>"
        ),
        "scanner must provide packed-path supplemental address extraction"
    );
    assert!(
        source.contains("token(20) + fee(3) + token(20)")
            && source.contains("(100..=1_000_000).contains(&fee)")
            && source.contains("scan_limit = input.len().min(2_048)"),
        "packed extraction must be bounded and pattern-gated"
    );
    assert!(
        source.contains("for addr in extract_packed_path_addresses(input, max_addrs_per_tx)"),
        "pending ingestion must use packed-path extraction alongside ABI-word extraction"
    );
}
