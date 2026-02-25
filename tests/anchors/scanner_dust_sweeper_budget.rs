use std::fs;

#[test]
fn test_scanner_dust_sweeper_budget_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");

    assert!(
        scanner.contains("SCAN_DUST_SWEEPER_MAX_PER_BLOCK")
            && scanner.contains("load_dust_sweeper_max_per_block")
            && scanner.contains("candidates.truncate(max_dust_checks)"),
        "scanner dust sweeper must enforce a bounded per-block RPC budget"
    );
}
