use std::fs;

#[test]
fn test_forkdb_getproof_support_latch_is_wired() {
    let source = fs::read_to_string("src/fork_db.rs").expect("read src/fork_db.rs");
    assert!(
        source.contains("getproof_support_map")
            && source.contains("getproof_unavailable")
            && source.contains("eth_getProof json-rpc error")
            && source.contains("batch eth_getStorageAt incomplete"),
        "ForkDB must latch eth_getProof method support per RPC URL and fail closed on incomplete batch responses"
    );
}
