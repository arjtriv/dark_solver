use std::fs;

#[test]
fn multi_sender_schedule_is_wired_into_context_opcodes() {
    let state = fs::read_to_string("src/symbolic/state.rs").expect("state source must be readable");
    assert!(
        state.contains("tx_sender_schedule"),
        "SymbolicMachine must store a tx_sender_schedule"
    );
    assert!(
        state.contains("effective_tx_origin"),
        "SymbolicMachine must expose effective_tx_origin helper"
    );

    let context = fs::read_to_string("src/symbolic/opcodes/context.rs")
        .expect("context opcode source must be readable");
    assert!(
        context.contains("effective_top_level_msg_sender"),
        "CALLER opcode must consult effective_top_level_msg_sender for top-level calls"
    );
    assert!(
        context.contains("effective_tx_origin"),
        "ORIGIN opcode must consult effective_tx_origin"
    );

    let engine =
        fs::read_to_string("src/symbolic/engine.rs").expect("engine source must be readable");
    assert!(
        engine.contains("effective_tx_origin"),
        "Inspector call logic must use effective_tx_origin for origin-dependent checks"
    );
}
