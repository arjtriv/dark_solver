use std::fs;

#[test]
fn test_verifier_panic_decode_does_not_default_malformed_to_zero() {
    let source =
        fs::read_to_string("src/executor/verifier.rs").expect("read src/executor/verifier.rs");

    assert!(
        !source.contains("u256_word_to_usize(&output[4..36]).unwrap_or(0)"),
        "verifier panic(uint256) decode must not silently default malformed panic payloads to code 0"
    );
    assert!(
        source.contains("panic_code=<malformed>") && source.contains("match code"),
        "verifier panic(uint256) decode should report malformed payload explicitly"
    );
}
