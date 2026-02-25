use std::fs;

#[test]
fn test_slippage_oracle_decode_fail_closed_on_malformed_quoter_response() {
    let source =
        fs::read_to_string("src/solver/liquidity.rs").expect("read src/solver/liquidity.rs");
    assert!(
        !source.contains("decode_u256_word(raw.as_ref(), 0).unwrap_or(U256::ZERO)"),
        "slippage oracle must not silently coerce malformed quote payloads to zero"
    );
    assert!(
        source.contains("slippage oracle returned malformed quote payload")
            && source.contains("ok_or_else"),
        "slippage oracle decode path must raise an error on malformed quoter output"
    );
}
