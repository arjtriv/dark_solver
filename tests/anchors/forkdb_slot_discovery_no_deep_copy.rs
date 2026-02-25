use std::fs;

#[test]
fn test_forkdb_slot_discovery_avoids_bytecode_deep_copy() {
    let source = fs::read_to_string("src/fork_db.rs").expect("read fork_db.rs");
    let start = source
        .find("async fn discover_storage_slots_async")
        .expect("discover_storage_slots_async must exist");
    let end = source[start..]
        .find("async fn scan_storage_fallback_async")
        .map(|idx| start + idx)
        .expect("scan_storage_fallback_async must exist");
    let section = &source[start..end];

    assert!(
        section.contains("let code_res: Option<alloy::primitives::Bytes>")
            && section.contains("Ok(code)")
            && section
                .contains("discover_storage_slots_from_bytecode(code_bytes.as_ref(), max_slots)"),
        "slot discovery must operate on borrowed Bytes slices instead of deep-copying code"
    );
    assert!(
        !section.contains("Ok(code.to_vec())"),
        "discover_storage_slots_async must not call code.to_vec() in the hot path"
    );
}
