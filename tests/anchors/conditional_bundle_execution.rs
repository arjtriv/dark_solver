//! Anchor: conditional bundle execution is wired via per-step `execute_if` storage predicates.

#[test]
fn conditional_bundle_execution_is_wired() {
    let core = include_str!("../../src/tactics/objectives/core.rs");
    assert!(
        core.contains("ExecuteIfStorageEq"),
        "core must define ExecuteIfStorageEq"
    );
    assert!(
        core.contains("execute_if"),
        "ExploitStep must carry an execute_if field"
    );

    let executor = include_str!("../../src/executor/mod.rs");
    assert!(
        executor.contains("DroppedConditional"),
        "executor must expose a dropped outcome for conditional aborts"
    );
    assert!(
        executor.contains("execute_if"),
        "executor must read execute_if predicates to gate private submission submission"
    );
}
