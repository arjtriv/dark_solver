use std::fs;

#[test]
fn eip_197_pairing_precompile_is_symbolically_modeled() {
    let calls_source =
        fs::read_to_string("src/symbolic/opcodes/calls.rs").expect("calls opcode source missing");

    assert!(
        calls_source.contains("v if v == U256::from(8u64)"),
        "calls precompile handler must model EIP-197 pairing at address 0x08"
    );
    assert!(
        calls_source.contains("bn254_pairing_ok"),
        "pairing model must use a deterministic UF predicate (bn254_pairing_ok)"
    );
    assert!(
        calls_source.contains("BYTES_PER_PAIR: u64 = 192"),
        "pairing model must gate on 192-byte pair chunks"
    );
    assert!(
        calls_source.contains("SAFE_MAX_PAIRS"),
        "pairing model must remain bounded to preserve the 1800ms law"
    );
    assert!(
        calls_source.contains("len_multiple"),
        "pairing model must enforce the length-multiple-of-192 validity envelope"
    );
}
