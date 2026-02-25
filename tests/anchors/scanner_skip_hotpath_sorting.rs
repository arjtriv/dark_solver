use std::fs;

#[test]
fn test_scanner_skips_hotpath_sorting_outside_tests() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("if cfg!(test) {")
            && source.contains("Preserve deterministic order for tests")
            && source.contains("candidates.sort();"),
        "scanner candidate sorting must be test-only in hot paths"
    );
}
