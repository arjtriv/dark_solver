use std::fs;

#[test]
fn test_scanner_capital_profiler_is_timeboxed_with_carryover() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("CAPITAL_PROFILER_BLOCK_BUDGET_MS")
            && source.contains("load_capital_profiler_block_budget_ms"),
        "capital profiler must expose a per-block time budget control"
    );
    assert!(
        source.contains("take_capital_profiler_carryover")
            && source.contains("push_capital_profiler_carryover"),
        "capital profiler must carry over unfinished candidates across blocks"
    );
    assert!(
        source.contains("carryover_pending.extend_from_slice(&candidates[idx..]);")
            && source.contains("Capital profiler budget exhausted at block"),
        "time budget exhaustion must stop current pass and defer remaining candidates"
    );
}
