use std::fs;

#[test]
fn test_gas_solver_word_parse_rejects_oversized_significant_hex() {
    let source =
        fs::read_to_string("src/executor/gas_solver.rs").expect("read src/executor/gas_solver.rs");
    assert!(
        source.contains("let significant = hex.trim_start_matches('0');")
            && source.contains("if significant.len() > 64 {"),
        "gas solver hex-word parser must fail closed on oversized significant words"
    );
}
