use std::fs;

#[test]
fn test_scanner_fast_filter_gate_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");

    assert!(
        scanner.contains("SCAN_FAST_FILTER_ALLOW_ALL")
            && scanner.contains("fast_filter_allow_all_enabled")
            && scanner.contains("_ => fast_filter_allow_all_enabled()"),
        "scanner fast filter must not be unconditional allow-all by default"
    );
}
