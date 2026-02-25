use std::fs;

#[test]
fn eip_196_bn254_add_and_mul_precompiles_are_symbolically_modeled() {
    let calls_source =
        fs::read_to_string("src/symbolic/opcodes/calls.rs").expect("calls opcode source missing");

    assert!(
        calls_source.contains("v if v == U256::from(6u64)"),
        "precompile handler must model EIP-196 bn254 add at address 0x06"
    );
    assert!(
        calls_source.contains("bn254_add_x") && calls_source.contains("bn254_add_y"),
        "bn254 add model must use deterministic UFs for x/y coordinates"
    );
    assert!(
        calls_source.contains("v if v == U256::from(7u64)"),
        "precompile handler must model EIP-196 bn254 mul at address 0x07"
    );
    assert!(
        calls_source.contains("bn254_mul_x") && calls_source.contains("bn254_mul_y"),
        "bn254 mul model must use deterministic UFs for x/y coordinates"
    );
    assert!(
        calls_source.contains("modeled_size") && calls_source.contains("U256::from(64u64)"),
        "handled precompile path must set RETURNDATASIZE-compatible modeled return lengths"
    );
}
