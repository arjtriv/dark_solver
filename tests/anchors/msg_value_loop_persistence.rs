use std::fs;

#[test]
fn test_msg_value_loop_persistence_guard_is_wired() {
    let state_source = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for msg.value loop audit");
    let calls_source = fs::read_to_string("src/symbolic/opcodes/calls.rs")
        .expect("src/symbolic/opcodes/calls.rs must be readable for msg.value loop audit");

    assert!(
        state_source.contains("track_msg_value_loop_guard"),
        "symbolic state must expose msg.value loop guard tracking"
    );
    assert!(
        state_source.contains("self.value_transfer_call_count > 1"),
        "msg.value loop guard must activate on repeated value-carrying calls"
    );
    assert!(
        state_source.contains("sender_balance.bvuge(&self.cumulative_call_value_out)"),
        "msg.value loop guard must assert sender balance covers cumulative call-value outflow"
    );
    assert!(
        calls_source.contains("machine.track_msg_value_loop_guard(sender, value_bv);"),
        "CALL/CALLCODE handling must invoke msg.value loop guard tracking"
    );
}
