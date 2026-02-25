use std::fs;

#[test]
fn test_executor_failed_step_guard_is_wired() {
    let executor =
        fs::read_to_string("src/executor/mod.rs").expect("src/executor/mod.rs must be readable");

    assert!(
        executor.contains("let failed_index = report.failed_step?;")
            && executor.contains("Skipping honeypot marker: missing failed_step")
            && executor.contains("Skipping gas-grief marker: missing failed_step"),
        "executor must require explicit in-bounds failed_step before learning selector-blocking side effects"
    );
}
