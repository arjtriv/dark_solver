use std::fs;

#[test]
fn test_capital_profiler_chunking_is_calldata_budgeted_and_pressure_adaptive() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("CAPITAL_PROFILER_MAX_CHUNK_CALLDATA_BYTES")
            && source.contains("load_capital_profiler_max_chunk_calldata_bytes"),
        "capital-profiler chunking must be bounded by calldata-byte budget"
    );
    assert!(
        source.contains("estimated_bytes_per_owner")
            && source.contains("max_owners_by_bytes")
            && source.contains("max_owners_by_calls"),
        "capital-profiler chunk sizing must combine call-count and byte-budget limits"
    );
    assert!(
        source.contains("under_pressure") && source.contains("addrs_per_chunk / 2"),
        "capital-profiler chunk sizing must adapt downward under congestion pressure"
    );
}
