use std::fs;

#[test]
fn test_forkdb_getproof_uses_b256_storage_keys_not_hex_strings() {
    let source = fs::read_to_string("src/fork_db.rs").expect("read fork_db.rs");
    assert!(
        source.contains("alloy::primitives::B256::from(slot.to_be_bytes::<32>())"),
        "eth_getProof storage key encoding must use fixed-size B256 conversion"
    );
    assert!(
        !source.contains(".map(Self::storage_key_hex_from_slot)"),
        "eth_getProof hot path must avoid per-slot String key building"
    );
}
