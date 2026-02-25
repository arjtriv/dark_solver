use std::fs;

#[test]
fn test_fail_closed_submission_and_solver_guards_are_wired() {
    let executor =
        fs::read_to_string("src/executor/mod.rs").expect("src/executor/mod.rs must be readable");
    let builders = fs::read_to_string("src/executor/builders.rs")
        .expect("src/executor/builders.rs must be readable");
    let runner =
        fs::read_to_string("src/solver/runner.rs").expect("src/solver/runner.rs must be readable");
    let gas_solver = fs::read_to_string("src/executor/gas_solver.rs")
        .expect("src/executor/gas_solver.rs must be readable");

    assert!(
        executor.contains("force_sync_nonce")
            && executor.contains("Failed to sync nonce")
            && executor.contains("DroppedPreflight"),
        "executor must fail closed when nonce sync fails"
    );
    assert!(
        executor.contains("Failed to fetch latest block before dispatch")
            && executor.contains("DroppedPreflight"),
        "executor must fail closed when latest head fetch fails before dispatch"
    );
    assert!(
        executor.contains("expected_profit is missing")
            && executor.contains("u256_to_u128_saturating"),
        "executor must gate private submission bidding on valid expected_profit"
    );

    assert!(
        builders.contains("classify_bundle_submission_response")
            && builders.contains("jsonrpc error")
            && builders.contains("invalid JSON-RPC success body"),
        "builder submission must reject HTTP 2xx bodies that are JSON-RPC errors/malformed"
    );
    assert!(
        builders.contains("returned malformed JSON-RPC during handshake")
            && builders.contains("failed handshake: HTTP"),
        "private handshake must fail closed on malformed/non-2xx responses"
    );

    assert!(
        runner.contains("worker_failed") && runner.contains("return Vec::new()"),
        "parallel objective runner must fail closed on worker panic/cancel"
    );

    assert!(
        gas_solver.contains("FEE_HISTORY_TIMEOUT_MS")
            && gas_solver.contains("body.get(\"error\").is_some()")
            && gas_solver.contains("resp.json::<serde_json::Value>()"),
        "gas solver must use bounded fee-history/oracle decode paths and reject JSON-RPC errors"
    );
}
