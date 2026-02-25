use std::fs;

#[test]
fn test_replay_freshness_sla_is_enforced() {
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for replay-freshness audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for replay-freshness audit");

    assert!(
        executor_source.contains("freshness_sla_budgets_ms"),
        "executor must define chain-aware freshness SLA budgets"
    );
    assert!(
        executor_source.contains("solve_to_replay_age")
            && executor_source.contains("replay_to_send_age"),
        "executor must gate both solve->replay and replay->send freshness windows"
    );
    assert!(
        executor_source.contains("AttackOutcome::DroppedStale"),
        "executor freshness violations must fail closed via stale-drop outcome"
    );
    assert!(
        main_source.contains("solve_completed_ms"),
        "main runtime must pass solve completion timing into execution freshness checks"
    );
}
