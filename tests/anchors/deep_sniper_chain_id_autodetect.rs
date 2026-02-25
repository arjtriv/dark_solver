use std::fs;

#[test]
fn deep_sniper_chain_id_is_auto_detected_or_explicit() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read src/bin/deep_sniper.rs");
    assert!(
        !source.contains("const DEFAULT_CHAIN_ID: u64 = 8453;"),
        "deep_sniper must not hardcode Base chain-id fallback"
    );
    assert!(
        source.contains("provider.get_chain_id()")
            && source.contains("timed out auto-detecting chain id from RPC; pass --chain-id explicitly"),
        "deep_sniper must auto-detect chain id from RPC with bounded timeout and explicit fallback guidance"
    );
}
