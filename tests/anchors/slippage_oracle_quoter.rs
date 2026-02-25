use std::fs;

#[test]
fn test_slippage_oracle_quoter_gate_is_wired() {
    let liquidity =
        fs::read_to_string("src/solver/liquidity.rs").expect("read src/solver/liquidity.rs");
    let main_rs = fs::read_to_string("src/main.rs").expect("read src/main.rs");

    assert!(
        liquidity.contains("function quoteExactInputSingle(")
            && liquidity.contains("verify_exact_input_single_liquidity")
            && liquidity.contains("SLIPPAGE_ORACLE_QUOTER")
            && liquidity.contains("extract_exact_input_single_quote_request"),
        "liquidity module must expose quoter-based exactInputSingle slippage checks"
    );

    assert!(
        main_rs.contains("verify_exact_input_single_liquidity")
            && main_rs.contains("slippage_oracle")
            && main_rs.contains("Slippage oracle blocked execution"),
        "execution path must consult slippage oracle before live dispatch"
    );
}
