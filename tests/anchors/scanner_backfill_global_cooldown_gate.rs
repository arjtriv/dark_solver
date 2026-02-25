use std::fs;

#[test]
fn test_scanner_backfill_global_cooldown_gate_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("[BACKFILL] Global RPC cooldown active; skipping cycle."),
        "Backfill should emit explicit signal when skipping cycles during global cooldown."
    );
    assert!(
        source.contains("if crate::utils::rpc::global_rpc_cooldown_active()"),
        "Backfill worker must check process-wide RPC cooldown before hydration cycle."
    );
}
