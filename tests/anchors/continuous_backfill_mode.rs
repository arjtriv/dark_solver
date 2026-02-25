use std::fs;

#[test]
fn test_continuous_backfill_mode_is_wired() {
    let scanner_source = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for backfill-mode audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for backfill-mode audit");

    assert!(
        scanner_source.contains("pub async fn start_backfill_worker"),
        "scanner must expose start_backfill_worker for historical scan mode"
    );
    assert!(
        scanner_source.contains("BACKFILL_START_OFFSET"),
        "backfill worker must expose start-offset control"
    );
    assert!(
        scanner_source.contains("BACKFILL_POLL_MS"),
        "backfill worker must expose polling-rate control"
    );
    assert!(
        scanner_source.contains("fn load_backfill_enabled() -> bool")
            && scanner_source.contains("BACKFILL_ENABLED")
            && scanner_source.contains("Err(_) => true"),
        "backfill must be enabled by default (disable explicitly with BACKFILL_ENABLED=false)"
    );
    assert!(
        main_source.contains("scanner::start_backfill_worker("),
        "main runtime must spawn backfill worker"
    );
}
