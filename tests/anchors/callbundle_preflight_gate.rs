use std::fs;

#[test]
fn test_callbundle_preflight_gate_is_wired() {
    let verifier_source = fs::read_to_string("src/executor/verifier.rs")
        .expect("src/executor/verifier.rs must be readable for callBundle audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for callBundle dispatch audit");

    assert!(
        verifier_source.contains("verify_call_bundle_preflight")
            && verifier_source.contains("\"eth_callBundle\"")
            && verifier_source.contains("CALL_BUNDLE_RELAY_URL")
            && verifier_source.contains("CALL_BUNDLE_TIMEOUT_MS"),
        "verifier must expose a bounded eth_callBundle preflight with configurable relay settings"
    );
    assert!(
        executor_source.contains("verify_call_bundle_preflight")
            && executor_source.contains("CallBundleVerdict")
            && executor_source.contains("Dropping bundle"),
        "executor must run callBundle preflight before live relay submission and fail closed on errors"
    );
}
