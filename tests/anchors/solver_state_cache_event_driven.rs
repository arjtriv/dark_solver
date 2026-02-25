use std::fs;

#[test]
fn test_solver_state_cache_is_event_driven_from_scanner_logs() {
    let watch_cache =
        fs::read_to_string("src/solver/watch_cache.rs").expect("read src/solver/watch_cache.rs");
    let scanner = fs::read_to_string("src/scanner.rs").expect("read src/scanner.rs");

    assert!(
        watch_cache.contains("DashMap")
            && watch_cache.contains("pub struct UniV2State")
            && watch_cache.contains("pub struct UniV3State")
            && watch_cache.contains("ingest_amm_log")
            && watch_cache.contains("Sync(uint112,uint112)")
            && watch_cache.contains("Swap(address,address,int256,int256,uint160,uint128,int24)"),
        "solver watch cache must track UniV2 and UniV3 state from Sync/Swap log payloads"
    );

    assert!(
        scanner.contains("build_amm_watch_filter")
            && scanner.contains("subscribe_logs(&filter)")
            && scanner.contains("ingest_amm_log(&log)")
            && scanner.contains("AMM watch cache logs"),
        "scanner must feed the watch cache from live EthLog subscriptions"
    );
}
