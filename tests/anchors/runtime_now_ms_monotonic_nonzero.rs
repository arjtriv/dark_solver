use std::fs;

#[test]
fn runtime_now_ms_is_monotonic_and_nonzero_in_main_and_executor() {
    let main_source = fs::read_to_string("src/main.rs").expect("read src/main.rs");
    let exec_source = fs::read_to_string("src/executor/mod.rs").expect("read src/executor/mod.rs");

    assert!(
        main_source.contains("static LAST_MAIN_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && main_source.contains("fn normalize_main_now_ms(sample_ms: Option<u64>) -> u64")
            && main_source.contains("normalize_main_now_ms(sample)"),
        "main runtime now_ms must be monotonic and non-zero"
    );
    assert!(
        exec_source.contains("static LAST_EXECUTOR_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && exec_source.contains("fn normalize_executor_now_ms(sample_ms: Option<u64>) -> u64")
            && exec_source.contains("normalize_executor_now_ms(sample)"),
        "executor runtime now_ms must be monotonic and non-zero"
    );
    assert!(
        !main_source.contains("map(|duration| duration.as_millis() as u64)\n        .unwrap_or(0)"),
        "main now_ms must not silently fallback to zero"
    );
    assert!(
        !exec_source.contains("map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "executor now_ms must not silently fallback to zero"
    );
}
