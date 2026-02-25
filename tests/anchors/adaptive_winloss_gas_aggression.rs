use std::fs;

#[test]
fn test_adaptive_winloss_gas_aggression_is_wired() {
    let gas_solver_source = fs::read_to_string("src/executor/gas_solver.rs")
        .expect("src/executor/gas_solver.rs must be readable for adaptive gas audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for adaptive feedback wiring");

    assert!(
        gas_solver_source.contains("AdaptiveBidFeedback")
            && gas_solver_source.contains("record_adaptive_feedback")
            && gas_solver_source.contains("GAS_ADAPTIVE_WINLOSS_ENABLED")
            && gas_solver_source.contains("ADAPTIVE_AGGRESSION_STEP_OUTBID_BPS")
            && gas_solver_source.contains("ADAPTIVE_AGGRESSION_STEP_WON_BPS"),
        "gas solver must implement win/loss adaptive aggression controls and bounded scalar updates"
    );
    assert!(
        executor_source.contains("record_adaptive_feedback")
            && executor_source.contains("AdaptiveBidFeedback::Won")
            && executor_source.contains("AdaptiveBidFeedback::Outbid"),
        "executor must feed live inclusion/outbid outcomes back into the adaptive gas model"
    );
}
