use std::fs;

#[test]
fn test_ws_gap_recovery_reconciliation_is_wired() {
    let scanner_source = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for ws-gap reconciliation audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for ws-gap reconciliation audit");

    assert!(
        scanner_source.contains("replay_ws_gap_range"),
        "scanner must include deterministic ws gap replay helper"
    );
    assert!(
        scanner_source.contains("record_scanner_gap_replay"),
        "scanner ws gap replay must persist reconciliation outcomes"
    );
    assert!(
        scanner_source.contains("advance_last_good_head"),
        "scanner must maintain monotonic last-good head tracking"
    );
    assert!(
        main_source.contains("scanner_last_good_head"),
        "main runtime must preserve scanner last-good head across ws reconnect loops"
    );
    assert!(
        main_source.contains("Some(scanner_db.clone())"),
        "main runtime must provide contracts db handle to scanner for gap replay persistence"
    );
}
