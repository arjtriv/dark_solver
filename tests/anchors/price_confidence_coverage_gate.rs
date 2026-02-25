use std::fs;

#[test]
fn test_price_confidence_coverage_gate_is_wired() {
    let verifier_source = fs::read_to_string("src/executor/verifier.rs")
        .expect("src/executor/verifier.rs must be readable for price-confidence gate audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for price-confidence gate audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for price-confidence gate audit");

    assert!(
        verifier_source.contains("stale_priced_tokens")
            && verifier_source.contains("PROFIT_TOKEN_PRICE_AGE_MS")
            && verifier_source.contains("PROFIT_PRICE_MAX_AGE_MS")
            && verifier_source.contains("PROFIT_BASE_PRICE_AGE_MS"),
        "verifier must compute stale-priced token coverage from explicit freshness thresholds"
    );
    assert!(
        verifier_source.contains("\"override\"")
            && verifier_source.contains("\"weth_parity\"")
            && verifier_source.contains("\"stable_proxy\""),
        "verifier pricing path must use explicit source classes for covered tokens"
    );
    assert!(
        executor_source.contains("PRICE_CONFIDENCE_GATE_ENABLED")
            && executor_source.contains("PRICE_CONFIDENCE_MAX_UNPRICED_TOKENS")
            && executor_source.contains("PRICE_CONFIDENCE_MAX_STALE_PRICED_TOKENS")
            && executor_source.contains("AttackOutcome::DroppedPriceConfidence"),
        "executor must fail-close execution when unpriced/stale coverage exceeds configured thresholds"
    );
    assert!(
        main_source.contains("DroppedPriceConfidence"),
        "main runtime must persist price-confidence drop attribution labels"
    );
}
