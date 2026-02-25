use std::fs;

#[test]
fn test_unified_target_hydration_is_wired_once_per_solver_pass() {
    let setup_source = fs::read_to_string("src/solver/setup.rs")
        .expect("src/solver/setup.rs must be readable for hydration anchor");
    let runner_source = fs::read_to_string("src/solver/runner.rs")
        .expect("src/solver/runner.rs must be readable for hydration anchor");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for hydration anchor");

    assert!(
        setup_source.contains("pub struct TargetContext"),
        "setup must define a reusable TargetContext for shared hydration"
    );
    assert!(
        setup_source.contains("pub fn hydrate_target_context"),
        "setup must expose hydrate_target_context for one-shot per-target hydration"
    );
    assert!(
        setup_source.contains("function aggregate3("),
        "token hydration must define Multicall aggregate3 surface"
    );
    assert!(
        setup_source.contains("fetch_attacker_token_balances_multicall_async"),
        "setup must include multicall token hydration path"
    );
    assert!(
        setup_source.contains("if let Some(result) = multicall_result"),
        "token hydration must keep sequential fallback when multicall is unavailable"
    );
    assert!(
        runner_source.contains("enter_target_context"),
        "runner must install hydrated target context inside each objective worker"
    );
    assert!(
        main_source.contains("hydrate_target_context"),
        "main solver pass must hydrate target context before objective fan-out"
    );
}
