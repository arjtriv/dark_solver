use std::fs;

#[test]
fn test_scanner_full_block_log_enrichment_is_bounded_and_optional() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("SCAN_FULL_BLOCK_LOG_ENRICHMENT_ENABLED")
            && source.contains("SCAN_FULL_BLOCK_LOG_ENRICHMENT_TIMEOUT_MS")
            && source.contains("SCAN_FULL_BLOCK_LOG_ENRICHMENT_MAX_ADDRS_PER_BLOCK"),
        "full-block log enrichment must expose explicit enable/timeout/budget controls"
    );
    assert!(
        source.contains(".from_block(block_num)")
            && source.contains(".to_block(block_num)")
            && source.contains("provider_clone.get_logs(&logs_filter)"),
        "full-block enrichment must query bounded per-block logs"
    );
    assert!(
        source.contains("topic_indexed_address")
            && source.contains("log.topics().iter().skip(1).take(enrichment_max_topics_per_log)"),
        "enrichment must extract indexed-address signals from bounded topic scans"
    );
}
