use std::fs;

#[test]
fn operator_docs_keep_replay_and_pressure_flows_visible() {
    let ops = fs::read_to_string("docs/OPERATIONS.md").expect("read operations");
    let use_cases = fs::read_to_string("docs/USE_CASES.md").expect("read use cases");

    assert!(ops.contains("shadow_replay"), "operations doc should keep replay commands");
    assert!(ops.contains("pressure_report"), "operations doc should keep pressure checks");
    assert!(ops.contains("benchmark_rpc"), "operations doc should keep rpc benchmarking");
    assert!(use_cases.contains("Local Operator Session Hardening"));
}
