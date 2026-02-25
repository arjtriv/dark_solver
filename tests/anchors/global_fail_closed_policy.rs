use std::fs;

#[test]
fn test_global_fail_closed_policy_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for global fail-closed audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for global fail-closed audit");
    let scanner_source = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for global fail-closed audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for global fail-closed audit");

    assert!(
        main_source.contains("RUNTIME_FAIL_CLOSED_ON_UNCERTAINTY")
            && main_source.contains("persist_fail_closed_attempt")
            && main_source.contains("uncertainty_rpc_cooldown")
            && main_source.contains("uncertainty_drawdown_unavailable")
            && main_source.contains("uncertainty_per_block_loss_unavailable"),
        "runtime must fail close on uncertainty classes and persist deterministic blocked-attempt attribution"
    );
    assert!(
        main_source.contains("drift_governor_block_execution"),
        "runtime must block execution when unresolved realized-vs-expected drift breaches hard floor"
    );
    assert!(
        executor_source.contains("if !shadow_report.success")
            && executor_source.contains("if !shadow_report.profitable")
            && executor_source.contains("is_stale_solve")
            && executor_source.contains("AttackOutcome::DroppedStale")
            && executor_source.contains("AttackOutcome::DroppedPriceConfidence"),
        "executor must fail close on replay inconsistency, stale head windows, and unpriced/stale valuation coverage"
    );
    assert!(
        scanner_source.contains("classify_unknown_opstack_tx_type")
            && scanner_source.contains("record_unknown_opstack_tx_type"),
        "scanner must classify and persist decode ambiguity instead of silently dropping the signal"
    );
    assert!(
        storage_source.contains("DroppedSafetyRails")
            && storage_source.contains("DroppedStale")
            && storage_source.contains("DroppedPriceConfidence"),
        "persistence layer must carry deterministic fail-closed outcome labels"
    );
}
