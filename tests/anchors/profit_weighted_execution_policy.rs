use std::fs;

#[test]
fn test_profit_weighted_execution_policy_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for profit-weighted execution policy audit");
    let policy_source = fs::read_to_string("src/executor/execution_policy.rs").expect(
        "src/executor/execution_policy.rs must be readable for profit-weighted execution policy audit",
    );

    assert!(
        main_source.contains("RUNTIME_PROFIT_WEIGHTED_EXECUTION_POLICY")
            && main_source.contains("RUNTIME_PROFIT_WEIGHTED_RISK_BUDGET_WEI")
            && main_source.contains("RUNTIME_PROFIT_WEIGHTED_ROI_MULTIPLE"),
        "runtime must expose env controls for profit-weighted execution policy"
    );
    assert!(
        main_source.contains("ProfitWeightedExecutionPolicy")
            && main_source.contains("should_override_fail_closed")
            && main_source.contains("profit_weighted_uncertainty_override_reason"),
        "runtime must consult the profit-weighted override gate and persist override attribution"
    );
    assert!(
        policy_source.contains("pub struct ProfitWeightedExecutionPolicy")
            && policy_source.contains("should_override_fail_closed")
            && policy_source.contains("profit_to_risk_ratio_x_floor"),
        "execution policy module must implement deterministic profit-to-risk gating helpers"
    );
}
