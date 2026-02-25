use std::fs;

#[test]
fn test_setup_requires_chain_id_without_runtime_hardcode_fallback() {
    let source = fs::read_to_string("src/solver/setup.rs").expect("read solver/setup.rs");
    assert!(
        source.contains("fn modeling_chain_id() -> anyhow::Result<u64>")
            && source.contains("CHAIN_ID is required for solver modeling"),
        "solver setup must require explicit chain-id for runtime modeling"
    );
    assert!(
        !source.contains("unwrap_or(8453)"),
        "solver setup must not hardcode Base chain-id fallback in runtime path"
    );
}
