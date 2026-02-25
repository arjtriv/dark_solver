use std::fs;

#[test]
fn test_scanner_compact_error_is_single_pass_without_vec_join() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("fn compact_error(err: impl std::fmt::Display) -> String"),
        "scanner must expose compact_error helper"
    );
    assert!(
        source.contains("let mut prev_ws = false;")
            && source.contains("for ch in raw.chars()")
            && source.contains("ch.is_whitespace()"),
        "compact_error must use single-pass whitespace compaction"
    );
    assert!(
        !source.contains("split_whitespace().collect::<Vec<_>>().join(\" \")"),
        "compact_error must avoid vec+join allocation pattern"
    );
}
