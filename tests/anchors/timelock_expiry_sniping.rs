use std::fs;

#[test]
fn test_timelock_expiry_sniping_objective_is_wired_and_eta_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/timelock.rs")
        .expect("src/protocols/timelock.rs must be readable for timelock protocol audit");
    let executor_source = fs::read_to_string("src/executor/timelock_sniper.rs").expect(
        "src/executor/timelock_sniper.rs must be readable for timelock executor strategy audit",
    );
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct TimelockExpirySnipingObjective"),
        "solver must expose TimelockExpirySnipingObjective"
    );
    assert!(
        objective_source.contains("build_timelock_expiry_sniping_steps"),
        "timelock objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_timelock_expiry_pattern(bytecode)"),
        "timelock objective must gate on queue/execute time-locked bytecode surface"
    );
    assert!(
        protocol_source.contains("timelock_window_open"),
        "timelock protocol helper must constrain eta execution window"
    );
    assert!(
        executor_source.contains("should_snipe_execute"),
        "executor timelock strategy helper must expose ETA gate utility"
    );
    assert!(
        catalog_source.contains("TimelockExpirySnipingObjective"),
        "objective catalog must include TimelockExpirySnipingObjective"
    );
}
