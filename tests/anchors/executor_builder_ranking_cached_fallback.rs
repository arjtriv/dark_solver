use std::fs;

#[test]
fn test_executor_builder_ranking_uses_cached_fallback_with_throttled_warnings() {
    let source = fs::read_to_string("src/executor/mod.rs").expect("read executor/mod.rs");
    assert!(
        source.contains("warn_builder_ranking_throttled")
            && source.contains("Falling back to cached order"),
        "builder ranking failures must emit throttled warnings and explicit cached fallback attribution"
    );
    assert!(
        source.contains("Builder ranking DB open failed")
            && source.contains("Builder ranking stats query failed"),
        "db-open and stats-query failures must be surfaced, not silently ignored"
    );
    assert!(
        source.contains("return cached.1;"),
        "builder ranking errors must return last-known cached ordering"
    );
}
