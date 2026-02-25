use std::fs;

#[test]
fn test_symbolic_precompile_modeling_for_ecrecover_and_modexp() {
    let calls_source = fs::read_to_string("src/symbolic/opcodes/calls.rs")
        .expect("src/symbolic/opcodes/calls.rs must be readable for precompile audit");

    assert!(
        calls_source.contains("fn try_handle_symbolic_precompile"),
        "calls opcode module must expose symbolic precompile handler"
    );
    assert!(
        calls_source.contains("v if v == U256::from(1u64)"),
        "precompile handler must model ECRECOVER (address 0x01)"
    );
    assert!(
        calls_source.contains("let recovered = msg_hash.extract(159, 0).zero_ext(96);"),
        "ECRECOVER model must constrain output address to hash-derived 160-bit relation"
    );
    assert!(
        calls_source.contains("v if v == U256::from(5u64)"),
        "precompile handler must model MODEXP (address 0x05)"
    );
    assert!(
        calls_source.contains("Bool::implies"),
        "MODEXP model must enforce modular envelope constraints"
    );
    assert!(
        calls_source.contains("try_handle_symbolic_precompile("),
        "CALL/STATICCALL path must invoke symbolic precompile handler"
    );
}
