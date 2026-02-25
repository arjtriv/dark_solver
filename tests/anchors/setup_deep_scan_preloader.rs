use std::fs;

#[test]
fn test_setup_preloads_profit_track_state_for_deep_scans() {
    let setup = fs::read_to_string("src/solver/setup.rs").expect("read src/solver/setup.rs");
    let main_rs = fs::read_to_string("src/main.rs").expect("read src/main.rs");

    assert!(
        setup.contains("DEEP_SCAN_PRELOADER_STORAGE_LIMIT")
            && setup.contains("deep_scan_preloader_state_cache")
            && setup.contains("preload_profit_tracking_state(")
            && setup.contains("load_profit_tracking_tokens()")
            && setup.contains("preloaded_hit"),
        "setup must preload and consume PROFIT_TRACK_TOKENS state via a local cache"
    );

    assert!(
        main_rs.contains("preload_profit_tracking_state")
            && main_rs.contains("Preloaded")
            && main_rs.contains("PROFIT_TRACK_TOKENS"),
        "main startup should trigger deep-scan preloader and report loaded targets"
    );
}
