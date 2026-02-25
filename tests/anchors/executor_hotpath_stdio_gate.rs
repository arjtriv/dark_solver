use std::fs;

#[test]
fn test_executor_hotpath_stdio_is_gated_by_env_toggle() {
    let source = fs::read_to_string("src/executor/mod.rs").expect("read executor/mod.rs");
    assert!(
        source.contains("EXECUTOR_VERBOSE_HOTPATH_LOGS")
            && source.contains("executor_verbose_hotpath_logs_enabled"),
        "executor must expose an env-gated hotpath stdio toggle"
    );
    assert!(
        source.contains("macro_rules! println")
            && source.contains("macro_rules! eprintln")
            && source.contains("::std::println!")
            && source.contains("::std::eprintln!"),
        "executor stdio macros must route through a gate before writing to stdout/stderr"
    );
}
