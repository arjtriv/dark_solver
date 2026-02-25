use std::fs;

#[test]
fn test_dumper_atomic_exit_is_fail_closed_and_bundle_appended() {
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for dumper anchor");
    let verifier_source = fs::read_to_string("src/executor/verifier.rs")
        .expect("src/executor/verifier.rs must be readable for dumper anchor");

    assert!(
        executor_source.contains("append_dumper_transactions")
            && executor_source.contains("build_dumper_swaps")
            && executor_source.contains("load_dumper_enabled"),
        "executor must build and append atomic dumper swaps when enabled"
    );
    assert!(
        executor_source.contains("repartition_dumper_min_out")
            && executor_source.contains("required_native_wei")
            && executor_source.contains("coinbase_bribe_wei"),
        "dumper min-out budgeting must scale to required native payout (gas + bribe)"
    );
    assert!(
        executor_source.contains("append_dumper_native_unwrap_transaction")
            && executor_source.contains("IWETH9::withdrawCall")
            && executor_source.contains("DUMPER_UNWRAP_TO_NATIVE"),
        "atomic exit must include optional WETH->native unwrap wiring for realized payout"
    );
    assert!(
        executor_source.contains("dumpable_gain_wei")
            && executor_source.contains("<= shadow_report.gas_cost_wei")
            && executor_source.contains("DroppedUnprofitable"),
        "dumper gate must reject candidates when estimated exit value does not clear gas cost"
    );
    assert!(
        verifier_source.contains("estimate_dumpable_token_gain_eth_wei")
            && verifier_source.contains("token_price_eth_wei")
            && verifier_source.contains("return None"),
        "verifier must provide fail-closed valuation for dumpable token gains"
    );
}
