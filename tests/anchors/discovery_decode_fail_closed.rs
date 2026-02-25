use std::fs;

#[test]
fn test_discovery_factory_decoding_fails_closed_on_malformed_data() {
    let utils_mod = fs::read_to_string("src/utils/mod.rs").expect("read utils/mod.rs");
    let abi_utils = fs::read_to_string("src/utils/abi.rs").expect("read utils/abi.rs");
    let basescan = fs::read_to_string("src/basescan.rs").expect("read basescan.rs");
    let defillama = fs::read_to_string("src/defillama.rs").expect("read defillama.rs");

    assert!(
        utils_mod.contains("pub mod abi;"),
        "ABI decode helpers should live in shared utils"
    );
    assert!(
        abi_utils.contains("pub fn decode_abi_usize_at")
            && abi_utils.contains("pub fn decode_abi_address_array"),
        "shared ABI helpers should decode usize words and dynamic address arrays"
    );
    assert!(
        !basescan.contains("try_into().unwrap_or(0)")
            && !defillama.contains("try_into().unwrap_or(0usize)")
            && !defillama.contains("try_into().unwrap_or(0)"),
        "discovery feeds must not silently coerce malformed ABI lengths to zero"
    );
    assert!(
        !basescan.contains("get_block_number().await.unwrap_or(0)"),
        "basescan head lookups must not silently default failed RPC calls to block 0"
    );
    assert!(
        basescan.contains("decode_abi_address_array")
            && defillama.contains("decode_abi_address_array"),
        "both discovery feeds should use shared fail-closed address array decoding"
    );
}
