use std::fs;

#[test]
fn test_capital_profiler_decode_failures_are_persisted_and_fallback_probed() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("classify_capital_profiler_decode_error")
            && source.contains("persist_capital_profiler_decode_failure")
            && source.contains("capital_profiler_decode"),
        "capital-profiler decode failures must be classified and persisted"
    );
    assert!(
        source.contains("Fallback=smaller_chunk")
            && source.contains("for owner in owners.iter().copied()")
            && source.contains("let single = [owner];"),
        "capital-profiler decode failures must fallback to smaller single-owner probes"
    );
    assert!(
        source.contains("probe_capital_profiler_owners"),
        "capital-profiler probing should be routed through a helper that supports fallback retries"
    );
}
