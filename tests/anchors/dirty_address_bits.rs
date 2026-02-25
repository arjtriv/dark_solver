use std::fs;

#[test]
fn test_dirty_address_bits_are_guarded_by_clean_word_constraints() {
    let math_source = fs::read_to_string("src/symbolic/utils/math.rs")
        .expect("src/symbolic/utils/math.rs must be readable for dirty-address audit");
    let calls_source = fs::read_to_string("src/symbolic/opcodes/calls.rs")
        .expect("src/symbolic/opcodes/calls.rs must be readable for dirty-address audit");
    let context_source = fs::read_to_string("src/symbolic/opcodes/context.rs")
        .expect("src/symbolic/opcodes/context.rs must be readable for dirty-address audit");

    assert!(
        math_source.contains("pub fn clean_address_word"),
        "math utils must expose canonical 160-bit address cleanup helper"
    );
    assert!(
        calls_source.contains("enforce_clean_address_word(machine, &target_bv);"),
        "call target decoding must enforce clean address word"
    );
    assert!(
        calls_source.contains("enforce_clean_address_word(machine, &from_bv);")
            || calls_source.contains("enforce_clean_address_word(machine, &to_bv);"),
        "calldata-derived address arguments must enforce clean address words"
    );
    assert!(
        context_source.contains("enforce_clean_address_word(machine, &addr_bv);"),
        "context address opcodes must enforce clean address words"
    );
}
