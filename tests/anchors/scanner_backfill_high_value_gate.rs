use std::fs;

#[test]
fn test_scanner_backfill_high_value_gate_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");

    assert!(
        source.contains("let high_value_tvl_threshold_wei = load_high_value_tvl_threshold();"),
        "Backfill worker must load high-value TVL threshold."
    );
    assert!(
        source.contains("let prioritization = PrioritizationConfig {"),
        "Backfill worker must derive prioritization config for gating."
    );
    assert!(
        source.contains("maybe_enqueue_backfill_target("),
        "Backfill enqueue path must route through shared high-value admission helper."
    );
}
