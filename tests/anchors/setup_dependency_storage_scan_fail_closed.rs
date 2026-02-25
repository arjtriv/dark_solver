use std::fs;

#[test]
fn test_setup_dependency_storage_scan_does_not_default_to_empty_on_error() {
    let source = fs::read_to_string("src/solver/setup.rs").expect("read solver/setup.rs");
    assert!(
        source.contains("DEPENDENCY_STORAGE_SCAN_WARN_COUNT")
            && source.contains("dependency storage scan failed")
            && source.contains("Skipping dependency context."),
        "dependency storage scan failures must be warned/throttled and skipped explicitly"
    );
    assert!(
        !source.contains("scan_storage(dep_addr, storage_limit).unwrap_or_default()"),
        "dependency storage scan must not silently default errors into empty slot lists"
    );
}
