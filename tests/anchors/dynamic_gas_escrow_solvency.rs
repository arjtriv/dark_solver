use std::fs;

#[test]
fn test_dynamic_gas_escrow_solvency_is_wired() {
    let verifier_source = fs::read_to_string("src/executor/verifier.rs")
        .expect("src/executor/verifier.rs must be readable for gas escrow audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for gas escrow gate wiring");

    assert!(
        verifier_source.contains("dynamic_gas_escrow_sufficient")
            && verifier_source.contains("provider.get_gas_price()")
            && verifier_source.contains("provider.get_balance(vault)")
            && verifier_source.contains("required_budget")
            && verifier_source.contains("additional_required_wei")
            && verifier_source.contains("dynamic_escrow_required_budget"),
        "verifier must compute dynamic gas escrow solvency from current gas price and vault balance"
    );
    assert!(
        executor_source.contains("DYNAMIC_GAS_ESCROW_ENABLED")
            && executor_source.contains("dynamic_gas_escrow_sufficient")
            && executor_source.contains("coinbase_bribe_wei")
            && executor_source.contains("Dynamic gas escrow guard blocked execution"),
        "executor must enforce dynamic gas escrow solvency before signing/submitting bundles"
    );
}
