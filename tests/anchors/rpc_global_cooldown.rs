use std::fs;

#[test]
fn rpc_layer_enforces_global_cooldown_on_rate_limit() {
    let source = fs::read_to_string("src/utils/rpc.rs")
        .expect("src/utils/rpc.rs must be readable for cooldown audit");

    for needle in [
        "GLOBAL_RPC_COOLDOWN_UNTIL_MS",
        "await_global_rpc_cooldown().await",
        "is_rate_limited_rpc_error(&message)",
        "arm_global_rpc_cooldown_after_rate_limit();",
    ] {
        assert!(
            source.contains(needle),
            "rpc layer must contain `{needle}` for global cooldown protocol"
        );
    }
}
