use std::fs;

#[test]
fn test_forkdb_debug_storage_pool_resilience_is_wired() {
    let fork_db = fs::read_to_string("src/fork_db.rs").expect("src/fork_db.rs must be readable");

    assert!(
        fork_db.contains("debug_storageRangeAt(hydration pool)")
            && fork_db.contains("run_with_hydration_pool_retry"),
        "ForkDB debug storage scan must route through hydration pool retry path"
    );
    assert!(
        fork_db.contains("merge with sparse fallback")
            && fork_db.contains("scan_storage_fallback_async")
            && fork_db.contains("seen.insert"),
        "ForkDB debug storage failures must merge fallback slots to reduce partial-state risk"
    );
}
