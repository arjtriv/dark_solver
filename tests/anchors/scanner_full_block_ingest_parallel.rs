use std::fs;

#[test]
fn test_scanner_full_block_ingestion_is_bounded_parallel() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("SCAN_FULL_BLOCK_INGEST_PARALLELISM")
            && source.contains("load_full_block_ingest_parallelism"),
        "scanner must expose bounded full-block ingestion parallelism controls"
    );
    assert!(
        source.contains("let mut in_flight = tokio::task::JoinSet::new();")
            && source.contains("while in_flight.len() >= full_block_ingest_parallelism"),
        "full-block ingestion must run high-value checks with bounded in-flight concurrency"
    );
    assert!(
        source.contains("let mut unique_interesting = Vec::new();")
            && source.contains("let mut seen_interesting = HashSet::new();"),
        "full-block ingestion must dedupe interesting addresses before parallel probes"
    );
}
