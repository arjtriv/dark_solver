use std::fs;

#[test]
fn test_generalized_frontrun_mirror_strategy_is_wired() {
    let strategy = fs::read_to_string("src/strategies/generalized_frontrun.rs")
        .expect("src/strategies/generalized_frontrun.rs must be readable");
    let main_rs = fs::read_to_string("src/main.rs").expect("src/main.rs must be readable");

    assert!(
        strategy.contains("GENERALIZED_FRONTRUN_ENABLED")
            && strategy.contains("subscribe_full_pending_transactions")
            && strategy.contains("execute_attack(")
            && strategy.contains("GENERALIZED_FRONTRUN_MAX_PENDING_PER_SEC")
            && strategy.contains("GENERALIZED_FRONTRUN_MAX_CONCURRENT"),
        "mirror strategy must be opt-in and execute bounded pending-tx blind-copy attempts"
    );

    assert!(
        main_rs.contains("start_generalized_frontrun("),
        "main runtime must wire the generalized frontrun strategy task"
    );
}
