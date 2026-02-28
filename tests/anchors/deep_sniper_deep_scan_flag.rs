use std::fs;

#[test]
fn deep_sniper_deep_scan_flag_is_still_exposed() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(source.contains("--deep-scan"), "deep-scan flag should stay public");
    assert!(
        source.contains("OBJECTIVE_DEEP_SCAN"),
        "deep-scan flag should still drive the objective env"
    );
}
