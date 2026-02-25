use std::fs;

#[test]
fn test_runtime_safety_rails_fail_closed_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for runtime safety-rails audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for runtime safety-rails audit");

    assert!(
        main_source.contains("RUNTIME_KILL_SWITCH")
            && main_source.contains("RUNTIME_DRAWDOWN_CAP_WEI")
            && main_source.contains("RUNTIME_PER_BLOCK_LOSS_CAP_WEI")
            && main_source.contains("RUNTIME_FAIL_CLOSED_ON_UNCERTAINTY"),
        "runtime must load kill-switch/loss-cap/fail-closed safety rail controls"
    );
    assert!(
        main_source.contains("rolling_drawdown_wei")
            && main_source.contains("realized_loss_for_solve_block")
            && main_source.contains("persist_fail_closed_attempt"),
        "runtime must enforce rolling drawdown + per-block loss caps and persist blocked attempts"
    );
    assert!(
        storage_source.contains("DroppedSafetyRails")
            && storage_source.contains("realized_loss_for_solve_block"),
        "persistence layer must expose deterministic safety-rail attribution and per-block loss queries"
    );
}
