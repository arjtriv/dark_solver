//! Anchor: storage-slot batch discovery must be able to probe 100+ slots per RPC call.
//! We implement this via `eth_getProof(address, storageKeys[], blockTag)` parsing and slot-key
//! encoding (works even when JSON-RPC batch is disabled).

use dark_solver::fork_db::ForkDB;
use revm::primitives::U256;

#[test]
fn test_storage_key_hex_from_slot_is_32_bytes() {
    let slot = U256::from(1u64);
    let encoded = ForkDB::storage_key_hex_from_slot(slot);
    assert!(encoded.starts_with("0x"));
    assert_eq!(encoded.len(), 66, "expected 0x + 64 hex chars");
    assert!(encoded.ends_with("01"), "expected big-endian padding");
}

#[test]
fn test_parse_eth_getproof_storage_values_extracts_slot_map() {
    let v = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "storageProof": [
                {"key": "0x01", "value": "0x00", "proof": []},
                {"key": "0x02", "value": "0x05", "proof": []}
            ]
        }
    });

    let map = ForkDB::parse_eth_getproof_storage_values(&v).expect("parse getProof");
    assert_eq!(map.get(&U256::from(1u64)).copied(), Some(U256::ZERO));
    assert_eq!(map.get(&U256::from(2u64)).copied(), Some(U256::from(5u64)));
}
