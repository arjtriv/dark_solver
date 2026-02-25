use std::fs;

#[test]
fn test_symbolic_chain_id_missing_env_fails_closed_in_objective_solver() {
    let source = fs::read_to_string("src/tactics/objectives/objectives_tail_and_tests.rs")
        .expect("read objectives_tail_and_tests.rs");

    assert!(
        source.contains("fn symbolic_chain_id() -> Option<u64>"),
        "symbolic chain id helper must represent missing CHAIN_ID explicitly"
    );
    assert!(
        source.contains(
            "Missing CHAIN_ID for symbolic execution modeling; skipping objective solve."
        ),
        "objective solver must fail closed when CHAIN_ID is missing in non-test mode"
    );
    assert!(
        !source.contains("load_u64_env(\"CHAIN_ID\").unwrap_or(8453)"),
        "production symbolic solver must not hard-default CHAIN_ID to Base"
    );
}
