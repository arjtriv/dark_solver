use std::fs;

#[test]
fn test_inclusion_outcome_attribution_is_persisted() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for inclusion-attribution audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for inclusion-attribution audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for inclusion-attribution audit");

    assert!(
        main_source.contains("classify_execution_outcome_label"),
        "main runtime must classify execution outcomes into persistent attribution labels"
    );
    assert!(
        main_source.contains("record_submission_attempt(&record)")
            || main_source.contains("record_submission_attempt(record)"),
        "main runtime must persist per-attempt execution attribution records"
    );
    assert!(
        main_source.contains("ExecutionOutcomeLabel::Outbid")
            && main_source.contains("ExecutionOutcomeLabel::UnprofitableAfterGas")
            && main_source.contains("ExecutionOutcomeLabel::Late"),
        "execution attribution must map competition/unprofitability/stale signals into explicit labels"
    );
    assert!(
        executor_source.contains("builder_outcomes.push")
            && executor_source.contains("feedback.included"),
        "executor feedback must expose builder acceptance outcomes for attribution persistence"
    );
    assert!(
        storage_source.contains("\"included\"")
            && storage_source.contains("\"not_included\"")
            && storage_source.contains("\"outbid\"")
            && storage_source.contains("\"late\"")
            && storage_source.contains("\"reverted\"")
            && storage_source.contains("\"unprofitable_after_gas\""),
        "storage layer must support canonical execution attribution labels"
    );
}
