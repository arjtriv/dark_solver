use std::fs;

#[test]
fn test_cow_based_snapshotting_is_wired() {
    let state_source = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for COW snapshot audit");
    let engine_source = fs::read_to_string("src/symbolic/engine.rs")
        .expect("src/symbolic/engine.rs must be readable for COW snapshot audit");
    let memory_source = fs::read_to_string("src/symbolic/opcodes/memory.rs")
        .expect("src/symbolic/opcodes/memory.rs must be readable for COW snapshot audit");

    assert!(
        state_source.contains("storage_undo_log") && state_source.contains("visited_pcs_undo_log"),
        "symbolic state must track undo logs for storage and visited-pc mutations"
    );
    assert!(
        state_source.contains("storage_undo_len: usize")
            && state_source.contains("visited_pcs_undo_len: usize"),
        "snapshot schema must capture undo-log checkpoints instead of cloning heavy maps"
    );
    assert!(
        state_source.contains("set_storage_array")
            && state_source.contains("mark_visited_pc")
            && state_source.contains("clear_visited_pcs"),
        "state machine must expose copy-on-write mutation helpers for tracked fields"
    );
    assert!(
        !state_source.contains("capture: |machine| machine.storage.clone()")
            && !state_source.contains("capture: |machine| machine.visited_pcs.clone()"),
        "snapshot capture path must avoid full-map cloning for storage and visited PCs"
    );
    assert!(
        engine_source.contains("self.mark_visited_pc(pc)")
            && memory_source.contains("machine.set_storage_array(addr, new_storage)"),
        "runtime mutation sites must route through copy-on-write helpers"
    );
}
