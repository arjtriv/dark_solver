use std::fs;

#[test]
fn test_executor_deterministic_builder_ranking_is_wired() {
    let source = fs::read_to_string("src/executor/mod.rs").expect("read executor/mod.rs");
    assert!(
        source.contains("fn builder_routing_score("),
        "Executor must score builders via deterministic integer math."
    );
    assert!(
        source.contains(".then_with(|| a.builder.cmp(&b.builder))"),
        "Builder ranking must include stable tie-break ordering by builder name."
    );
    assert!(
        !source.contains(".partial_cmp(&score(a))"),
        "Float partial_cmp ranking path should be removed from builder ordering."
    );
}
