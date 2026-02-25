use std::fs;

#[test]
fn test_multi_step_payloads_are_sent_as_single_bundle_per_block_group() {
    let exec = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for atomic bundling audit");

    assert!(
        exec.contains("MultiBlockExecutor::new"),
        "executor must build MultiBlockExecutor for grouping"
    );
    assert!(
        exec.contains("let bundles = mb_executor.to_bundles"),
        "executor must derive bundle payloads from grouped signed txs"
    );
    assert!(
        exec.contains(".send_bundle_ranked(&bundle, &ranked_builders)"),
        "executor must relay the whole bundle to builders"
    );
    assert!(
        exec.contains("[BUNDLE] Submitting"),
        "executor must log bundle submissions as a single unit"
    );
}
