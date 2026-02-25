use alloy::primitives::Address;
use dark_solver::storage::contracts_db::{
    BuilderAttemptRecord, ContractsDb, ExecutionOutcomeLabel, SubmissionAttemptRecord,
};
use revm::primitives::U256 as RU256;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_db_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{}_{}.db", prefix, nanos))
}

#[test]
fn contested_benchmark_rows_dedupe_by_payload_json() {
    let path = temp_db_path("contested_bench_dedup_anchor");
    let db = ContractsDb::open(&path).expect("db open");

    let base = SubmissionAttemptRecord {
        target: Address::from([0xBB; 20]),
        objective: "anchor-contested".to_string(),
        solve_block: 777,
        solve_duration_ms: 500,
        solve_started_ms: 1,
        replay_completed_ms: Some(2),
        send_completed_ms: Some(3),
        tip_wei: Some(1),
        max_fee_wei: Some(2),
        expected_profit_wei: Some(RU256::from(1000u64)),
        realized_profit_wei: Some(RU256::from(900u64)),
        realized_profit_negative: false,
        latency_bucket_ms: Some(100),
        tip_band_wei: Some(1),
        chosen_builders: vec!["B1".to_string(), "B2".to_string()],
        outcome_label: ExecutionOutcomeLabel::NotIncluded,
        included: Some(false),
        reverted: Some(false),
        inclusion_block: None,
        contested: true,
        payload_json: Some("{\"payload\":\"same\"}".to_string()),
        details_json: None,
        builder_outcomes: vec![
            BuilderAttemptRecord {
                builder: "B1".to_string(),
                accepted: true,
                latency_ms: 40,
                rejection_class: None,
                response_message: None,
            },
            BuilderAttemptRecord {
                builder: "B2".to_string(),
                accepted: false,
                latency_ms: 75,
                rejection_class: Some("outbid".to_string()),
                response_message: None,
            },
        ],
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

    let rows = db.contested_benchmark_rows(10).expect("contested rows");
    assert_eq!(
        rows.len(),
        2,
        "expected contested benchmark to return latest attempt per payload (one row per builder outcome for that attempt)"
    );

    let builders: std::collections::BTreeSet<String> =
        rows.iter().map(|r| r.builder.clone()).collect();
    assert_eq!(builders.len(), 2);
    assert!(builders.contains("B1"));
    assert!(builders.contains("B2"));

    let _ = std::fs::remove_file(path);
}
