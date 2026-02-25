use std::fs;

#[test]
fn test_high_fidelity_storage_crawler_uses_sparse_probe_and_bytecode_discovery() {
    let fork_db = fs::read_to_string("src/fork_db.rs")
        .expect("src/fork_db.rs must be readable for storage crawler audit");
    let setup = fs::read_to_string("src/solver/setup.rs")
        .expect("src/solver/setup.rs must be readable for storage crawler audit");

    assert!(
        !setup.contains("Assuming zero-initialized storage."),
        "setup must not claim zero-initialized fallback storage"
    );
    assert!(
        setup.contains("sparse fallback-derived storage snapshot"),
        "setup warning must reflect sparse fallback behavior"
    );

    assert!(
        fork_db.contains("fn discover_storage_slots_from_bytecode"),
        "ForkDB must implement bytecode-based storage slot discovery"
    );
    assert!(
        fork_db.contains("let sequential = max_slots.min(101);"),
        "ForkDB fallback must probe common slots 0..100"
    );
    assert!(
        fork_db.contains("Self::discover_storage_slots_async")
            && fork_db.contains("Self::fallback_storage_slots(max_slots, &discovered_slots)"),
        "ForkDB sparse scan must include discovered slots from bytecode analysis"
    );
    assert!(
        fork_db.contains("if results.is_empty()")
            && fork_db.contains("Self::scan_storage_fallback_async"),
        "ForkDB must fail over to sparse eth_getStorageAt scanning when debug_storageRangeAt fails early"
    );
}
