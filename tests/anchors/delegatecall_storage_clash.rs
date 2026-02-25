use std::fs;

#[test]
fn test_delegatecall_storage_clash_detection_is_wired() {
    let state_source = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for delegatecall clash audit");
    let memory_source = fs::read_to_string("src/symbolic/opcodes/memory.rs")
        .expect("src/symbolic/opcodes/memory.rs must be readable for delegatecall clash audit");
    let engine_source = fs::read_to_string("src/symbolic/engine.rs")
        .expect("src/symbolic/engine.rs must be readable for delegatecall clash audit");
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        state_source.contains("delegatecall_storage_clash_detected"),
        "symbolic state must track delegatecall slot-clash signal"
    );
    assert!(
        state_source.contains("mark_delegatecall_sstore"),
        "symbolic state must expose delegatecall SSTORE clash checker"
    );
    assert!(
        memory_source.contains("machine.mark_delegatecall_sstore(&key);"),
        "SSTORE path must report writes into delegatecall clash checker"
    );
    assert!(
        engine_source.contains("CallScheme::DelegateCall"),
        "engine must track delegatecall depth across call/call_end"
    );
    assert!(
        objective_source.contains("DelegateCallStorageClashObjective"),
        "solver must expose delegatecall storage clash objective"
    );
    assert!(
        catalog_source.contains("DelegateCallStorageClashObjective"),
        "objective catalog must include delegatecall clash objective"
    );
}
