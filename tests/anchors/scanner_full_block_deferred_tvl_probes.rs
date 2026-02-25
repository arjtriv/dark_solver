use std::fs;

#[test]
fn test_scanner_full_block_uses_deferred_tvl_probe_lane_with_budget() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("SCAN_FULL_BLOCK_DEFERRED_HIGH_VALUE_PROBES_PER_BLOCK")
            && source.contains("load_full_block_deferred_high_value_probes_per_block"),
        "full-block scanner must expose a deferred high-value probe budget control"
    );
    assert!(
        source.contains("let mut deferred_high_value_candidates: Vec<Address> = Vec::new();")
            && source.contains("deferred_high_value_candidates.push(address);"),
        "uncached high-value candidates must be collected into a deferred probe lane"
    );
    assert!(
        source.contains("take(deferred_high_value_probe_budget_per_block)")
            && source.contains("reserve_target_probe(address)"),
        "deferred probes must remain strictly budgeted per block"
    );
}
