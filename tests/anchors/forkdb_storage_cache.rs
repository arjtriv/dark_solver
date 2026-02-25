use std::fs;

#[test]
fn test_forkdb_storage_cache_is_wired() {
    let fork_db = fs::read_to_string("src/fork_db.rs").expect("src/fork_db.rs must be readable");

    assert!(
        fork_db.contains("storage_cache")
            && fork_db.contains("MAX_STORAGE_CACHE_ENTRIES")
            && fork_db.contains("trim_storage_cache"),
        "ForkDB must define a bounded storage cache for replay hot-path reads"
    );
    assert!(
        fork_db.contains("storage_cache.get(&(addr, idx, block_number))")
            && fork_db.contains("storage_cache.insert((addr, idx, block_number), val)"),
        "ForkDB storage_ref must read/write cache for pinned block storage lookups"
    );
}
