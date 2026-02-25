use std::fs;

#[test]
fn test_scanner_public_ws_race_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");

    assert!(
        scanner.contains("SCAN_PUBLIC_WS_RACE_URLS")
            && scanner.contains("load_public_ws_race_urls")
            && scanner.contains("SCAN_PUBLIC_WS_RACE_CHANNEL_CAPACITY")
            && scanner.contains("tokio::sync::mpsc::channel::<HeadRaceEvent>")
            && scanner.contains("Multi-stream public head racing enabled"),
        "scanner must expose configurable public WS race feeds and a bounded head race channel"
    );

    assert!(
        scanner.contains("let mut last_dispatched_block = reconnect_head;")
            && scanner.contains("if block_num <= last_dispatched_block"),
        "scanner must dedupe stale/duplicate raced heads before dispatching block workers"
    );
}
