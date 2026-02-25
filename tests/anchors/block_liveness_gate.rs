use std::fs;

#[test]
fn test_executor_block_liveness_gate_is_enforced_before_bundle_send() {
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for block-liveness audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for block-liveness audit");

    assert!(
        executor_source.contains("fn is_stale_solve("),
        "executor must define a stale-solve predicate for block liveness"
    );
    assert!(
        executor_source.contains("current_latest_block > target_solve_block.saturating_add(1)"),
        "stale solve predicate must enforce latest > solve+1 hard-stop law"
    );
    assert!(
        executor_source.contains("[WARN] Stale Solve dropped:"),
        "executor must emit warning telemetry when stale solve is dropped"
    );
    assert!(
        executor_source.contains("self.provider.get_block_number().await"),
        "executor must query latest block before sending live bundle"
    );
    assert!(
        main_source.contains("execute_attack(")
            && main_source.contains("solve_target_block")
            && main_source.contains("require_late_solve_preflight"),
        "main pipeline must pass solve target block and late-solve preflight metadata into executor"
    );
}
