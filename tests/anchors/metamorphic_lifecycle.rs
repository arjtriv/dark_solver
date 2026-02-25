use std::fs;

#[test]
fn test_metamorphic_selfdestruct_lifecycle_is_modeled() {
    let state_source = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for metamorphic lifecycle audit");
    let control_source = fs::read_to_string("src/symbolic/opcodes/control.rs")
        .expect("src/symbolic/opcodes/control.rs must be readable for metamorphic lifecycle audit");
    let context_source = fs::read_to_string("src/symbolic/opcodes/context.rs")
        .expect("src/symbolic/opcodes/context.rs must be readable for metamorphic lifecycle audit");

    assert!(
        state_source.contains("pub fn record_selfdestruct(&mut self, contract: Address)"),
        "symbolic state must expose explicit selfdestruct lifecycle handler"
    );
    assert!(
        state_source.contains("self.set_storage_array(contract, self.zero_storage())"),
        "selfdestruct lifecycle must wipe storage to zero array"
    );
    assert!(
        state_source.contains("self.ext_code_hash_overrides"),
        "selfdestruct lifecycle must reset/ext override code hash to zero"
    );
    assert!(
        control_source.contains("machine.record_selfdestruct(destroyed_contract);"),
        "SELFDESTRUCT opcode path must invoke lifecycle handler"
    );
    assert!(
        context_source.contains("machine.ext_code_hash_overrides.get(&concrete_addr)"),
        "EXTCODEHASH must consult selfdestruct code-hash overrides"
    );
    assert!(
        context_source.contains("machine.destroyed_contracts.contains(&concrete_addr)"),
        "EXTCODEHASH/EXTCODESIZE must treat destroyed contracts as zero-code"
    );
}
