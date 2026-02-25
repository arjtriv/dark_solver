use alloy::primitives::Address;
use dark_solver::storage::contracts_db::{
    ContractsDb, ExecutionOutcomeLabel, SubmissionAttemptRecord,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use revm::primitives::U256 as RU256;

fn temp_db_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{}_{}.db", prefix, nanos))
}

#[test]
fn calibration_cases_dedupe_by_payload_json() {
    let path = temp_db_path("calibration_dedup_anchor");
    let db = ContractsDb::open(&path).expect("db open");

    let base = SubmissionAttemptRecord {
        target: Address::from([0xAA; 20]),
        objective: "anchor-calibration".to_string(),
        solve_block: 123,
        solve_duration_ms: 1000,
        solve_started_ms: 1,
        replay_completed_ms: Some(2),
        send_completed_ms: Some(3),
        tip_wei: None,
        max_fee_wei: None,
        expected_profit_wei: Some(RU256::from(1000u64)),
        realized_profit_wei: Some(RU256::from(900u64)),
        realized_profit_negative: false,
        latency_bucket_ms: None,
        tip_band_wei: None,
        chosen_builders: Vec::new(),
        outcome_label: ExecutionOutcomeLabel::NotIncluded,
        included: Some(false),
        reverted: Some(false),
        inclusion_block: None,
        contested: false,
        payload_json: Some("{\"payload\":\"same\"}".to_string()),
        details_json: None,
        builder_outcomes: Vec::new(),
    };

    let first_id = db
        .record_submission_attempt(base.clone())
        .expect("insert attempt");
    assert!(first_id > 0);

    let mut second = base.clone();
    second.realized_profit_wei = Some(RU256::from(1u64));
    let second_id = db
        .record_submission_attempt(second)
        .expect("insert second attempt");
    assert!(second_id > first_id);

    let cases = db.recent_calibration_cases(10).expect("cases");
    assert_eq!(
        cases.len(),
        1,
        "expected calibration cases to de-duplicate identical payload_json submissions"
    );
    assert_eq!(cases[0].attempt_id, second_id);

    let _ = std::fs::remove_file(path);
}
