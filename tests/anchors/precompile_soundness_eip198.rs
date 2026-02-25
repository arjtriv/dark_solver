use std::fs;

#[test]
fn modexp_precompile_is_length_bounded_and_header_parsed() {
    let calls_source =
        fs::read_to_string("src/symbolic/opcodes/calls.rs").expect("calls opcode source missing");

    assert!(
        calls_source.contains("MODEXP_HEADER_BYTES"),
        "MODEXP model must define the EIP-198 header size"
    );
    assert!(
        calls_source.contains("MODEXP_MAX_COMPONENT_LEN_BYTES"),
        "MODEXP model must bound base/exp/mod limb lengths"
    );
    assert!(
        calls_source.contains("MODEXP_MAX_TOTAL_INPUT_BYTES"),
        "MODEXP model must bound total input size to preserve gas/1800ms envelope"
    );
    assert!(
        calls_source.contains("let base_len = machine.read_word(args_off.clone())"),
        "MODEXP model must read baseLen from args memory"
    );
    assert!(
        calls_source.contains("let exp_len = machine.read_word(args_off.bvadd(&off_32))"),
        "MODEXP model must read expLen from args memory"
    );
    assert!(
        calls_source.contains("let mod_len = machine.read_word(args_off.bvadd(&off_64))"),
        "MODEXP model must read modLen from args memory"
    );
    assert!(
        calls_source.contains("machine.solver.assert(&args_len.bvule(&max_total))"),
        "MODEXP model must clamp args_len to the bounded precompile envelope"
    );
    assert!(
        calls_source.contains("machine.solver.assert(&args_len.bvuge(&total_needed))"),
        "MODEXP model must require args_len to cover header + declared component lengths"
    );
}
