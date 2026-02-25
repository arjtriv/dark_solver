use std::fs;

#[test]
fn test_scanner_fallback_semaphores_are_split_by_lane() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("tx_by_hash_fallback_semaphore")
            && source.contains("receipt_fallback_semaphore")
            && source.contains("linkage_fallback_semaphore"),
        "scanner must expose dedicated fallback semaphores per workload lane"
    );
    assert!(
        source.contains("SCAN_TX_BY_HASH_FALLBACK_SEMAPHORE_LIMIT")
            && source.contains("SCAN_RECEIPT_FALLBACK_SEMAPHORE_LIMIT")
            && source.contains("SCAN_LINKAGE_SEMAPHORE_LIMIT"),
        "lane semaphores must be independently configurable"
    );
    assert!(
        !source.contains("FALLBACK_SEMAPHORE_LIMIT: usize = 5"),
        "single shared fallback semaphore limit must be removed"
    );
}
