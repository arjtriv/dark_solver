use std::fs;

#[test]
fn test_generational_state_indices_use_undo_log_checkpoints_not_map_clones() {
    let src = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for generational-index audit");

    // Generational indices here mean: snapshots store *indices* (undo-log lengths) and restores
    // roll state back by popping to that index, rather than cloning the whole storage map.
    assert!(
        src.contains("storage_undo_len: usize") && src.contains("visited_pcs_undo_len: usize"),
        "snapshot schema must store undo-log checkpoint indices"
    );
    assert!(
        src.contains("while machine.storage_undo_log.len() > snap.storage_undo_len")
            && src.contains("while machine.visited_pcs_undo_log.len() > snap.visited_pcs_undo_len"),
        "restore must roll back by popping undo logs to the checkpoint index"
    );
    assert!(
        !src.contains("capture: |machine| machine.storage.clone()"),
        "storage map must not be cloned during snapshot capture"
    );
}
