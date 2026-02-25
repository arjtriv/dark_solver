//! Anchor: recursive proxy resolver plumbing (EIP-1967 / EIP-897 / Diamond) must decode correctly
//! and persist proxy->implementation telemetry into ContractsDb.

use dark_solver::fork_db::{decode_abi_address_array, decode_low160_address_from_word};
use dark_solver::storage::contracts_db::ContractsDb;
use revm::primitives::{Address, U256};

fn abi_word_with_address(addr: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(addr.as_slice());
    out
}

#[test]
fn test_decode_low160_address_from_word_extracts_address() {
    let addr = Address::new([0x11; 20]);
    let word = U256::from_be_bytes(abi_word_with_address(addr));
    assert_eq!(decode_low160_address_from_word(word), Some(addr));
    assert_eq!(decode_low160_address_from_word(U256::ZERO), None);
}

#[test]
fn test_decode_abi_address_array_decodes_facet_addresses() {
    let a0 = Address::new([0x22; 20]);
    let a1 = Address::new([0x33; 20]);

    // ABI encode address[] {a0, a1}:
    // 0x00 offset=0x20
    // 0x20 len=2
    // 0x40 elem0
    // 0x60 elem1
    let mut out = Vec::new();
    out.extend_from_slice(&U256::from(32u64).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(2u64).to_be_bytes::<32>());
    out.extend_from_slice(&abi_word_with_address(a0));
    out.extend_from_slice(&abi_word_with_address(a1));

    let decoded = decode_abi_address_array(&out, 8);
    assert_eq!(decoded, vec![a0, a1]);

    let truncated = decode_abi_address_array(&out, 1);
    assert_eq!(truncated, vec![a0]);
}

#[test]
fn test_contracts_db_proxy_resolution_roundtrip() {
    let tmp = std::env::temp_dir();
    let uniq = format!(
        "dark_solver_proxy_resolutions_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let path = tmp.join(uniq);

    let db = ContractsDb::open(&path).expect("open contracts db");
    let proxy = alloy::primitives::Address::repeat_byte(0xAA);
    let impl0 = alloy::primitives::Address::repeat_byte(0xBB);
    let impl1 = alloy::primitives::Address::repeat_byte(0xCC);

    db.replace_proxy_resolutions(proxy, 8453, "diamond_facet", &[impl0, impl1])
        .expect("write proxy resolutions");
    let got = db
        .proxy_resolutions_for(proxy, 8453)
        .expect("read proxy resolutions");
    assert!(
        got.iter()
            .any(|(kind, addr)| kind == "diamond_facet" && *addr == impl0),
        "expected impl0 row"
    );
    assert!(
        got.iter()
            .any(|(kind, addr)| kind == "diamond_facet" && *addr == impl1),
        "expected impl1 row"
    );

    let _ = std::fs::remove_file(&path);
}
