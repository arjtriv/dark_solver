use std::fs;

#[test]
fn test_forkdb_debug_method_latch_isolation_is_wired() {
    let source = fs::read_to_string("src/fork_db.rs").expect("read fork_db.rs");

    assert!(
        source.contains("debug_storage_range_mode: Arc<AtomicU8>"),
        "ForkDB must keep debug-storage support state per instance."
    );
    assert!(
        !source.contains("static DEBUG_STORAGE_RANGE_MODE: AtomicU8"),
        "Process-global debug storage mode latch must not exist."
    );
    assert!(
        source.contains("let debug_storage_range_mode = self.debug_storage_range_mode.clone();"),
        "scan_storage must use instance-local debug mode state."
    );
}
