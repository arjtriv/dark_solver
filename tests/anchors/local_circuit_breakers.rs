use std::fs;

#[test]
fn test_local_circuit_breakers_are_wired() {
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for circuit-breaker audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for circuit-breaker feedback audit");

    assert!(
        executor_source.contains("VOLATILITY_CIRCUIT_BREAKERS_ENABLED")
            && executor_source.contains("VOLATILITY_BASE_FEE_THRESHOLD_WEI")
            && executor_source.contains("VOLATILITY_CONSECUTIVE_LOSSES_THRESHOLD")
            && executor_source.contains("VOLATILITY_RPC_LATENCY_THRESHOLD_MS")
            && executor_source.contains("defensive mode"),
        "executor must implement volatility circuit-breaker thresholds and defensive mode activation"
    );
    assert!(
        executor_source.contains("record_circuit_breaker_feedback")
            && executor_source.contains("volatility_loss_streak")
            && main_source.contains("record_circuit_breaker_feedback(&feedback)"),
        "runtime must feed execution outcomes into circuit-breaker loss streak state"
    );
}
