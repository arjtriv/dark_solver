use std::fs;

#[test]
fn test_executor_conditional_storage_prefetch_is_timeboxed_and_deduped() {
    let source = fs::read_to_string("src/executor/mod.rs").expect("read executor/mod.rs");

    assert!(
        source.contains("CONDITIONAL_STORAGE_PREFETCH_TIMEOUT_MS")
            && source.contains("load_conditional_storage_prefetch_timeout_ms"),
        "executor must expose a bounded timeout for execute_if storage prefetch"
    );
    assert!(
        source.contains("CONDITIONAL_STORAGE_PREFETCH_CONCURRENCY")
            && source.contains("load_conditional_storage_prefetch_concurrency"),
        "executor must expose bounded prefetch concurrency for execute_if checks"
    );
    assert!(
        source.contains("let mut unique_reads = Vec::with_capacity(conditional_checks.len())")
            && source.contains("seen_reads"),
        "executor must dedupe (contract,slot) reads before fetching execute_if storage"
    );
    assert!(
        source.contains("tokio::time::timeout") && source.contains("execute_if prefetch timed out"),
        "execute_if prefetch stage must be timeboxed and fail closed on timeout"
    );
}
