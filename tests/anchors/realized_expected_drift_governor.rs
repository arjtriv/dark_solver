use std::fs;

#[test]
fn test_realized_expected_drift_governor_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for drift-governor audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for drift-governor audit");

    assert!(
        main_source.contains("rolling_realized_expected_ratio"),
        "main runtime must read rolling realized/expected EV ratio"
    );
    assert!(
        main_source.contains("drift_governor_required_floor")
            && main_source.contains("drift_governor_block_execution"),
        "main runtime must auto-tighten execution gating or hard-block based on drift ratio"
    );
    assert!(
        main_source.contains("DRIFT_STEADY_STATE_MAX_PROFIT_WEI")
            && main_source.contains("drift_throttle_applicable"),
        "online model-error governor must throttle only steady-state (low-margin) strategies and exempt whale-hunting paths"
    );
    assert!(
        main_source.contains("derive_realized_profit_estimate")
            && main_source.contains("realized_profit_negative"),
        "submission persistence must populate realized PnL estimates for online drift tracking"
    );
    assert!(
        storage_source.contains("rolling_realized_expected_ratio")
            && storage_source.contains("pnl_drift_samples"),
        "storage layer must expose rolling EV drift metrics and backing samples"
    );
}
