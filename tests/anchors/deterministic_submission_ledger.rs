use std::fs;

#[test]
fn test_deterministic_submission_ledger_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for deterministic-ledger audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for deterministic-ledger audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for deterministic-ledger audit");

    assert!(
        main_source.contains("\"solve_started_ms\"")
            && main_source.contains("\"replay_completed_ms\"")
            && main_source.contains("\"send_completed_ms\"")
            && main_source.contains("\"chosen_builders\"")
            && main_source.contains("\"inclusion_receipts\""),
        "main runtime must persist canonical submission-ledger timing and builder receipt fields"
    );
    assert!(
        storage_source.contains("response_message TEXT")
            && storage_source.contains("table_has_column")
            && storage_source
                .contains("ALTER TABLE builder_submission_outcomes ADD COLUMN response_message"),
        "storage layer must persist inclusion receipts and auto-migrate existing DB schema"
    );
    assert!(
        storage_source.contains("tip_wei")
            && storage_source.contains("max_fee_wei")
            && storage_source.contains("chosen_builders")
            && storage_source.contains("replay_completed_ms")
            && storage_source.contains("send_completed_ms"),
        "submission ledger must persist bid params, builder set, and replay/send timestamps"
    );
    assert!(
        executor_source.contains("response_message: resp.message"),
        "executor feedback must carry builder response receipts into persistence"
    );
}
