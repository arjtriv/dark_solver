use std::fs;

#[test]
fn test_scanner_priority_tokens_require_priceability_and_non_zero_entries() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");

    assert!(
        scanner.contains("fn top_priority_tokens(chain_id: u64) -> Vec<Address>"),
        "priority token selection helper must exist"
    );
    assert!(
        scanner.contains("if token == Address::ZERO") && scanner.contains("continue;"),
        "priority token selection must filter Address::ZERO"
    );
    assert!(
        scanner.contains(
            "token_price_eth_wei(token, &chain_config, stable_price_eth_wei, price_overrides)"
        ) && scanner.contains("is_none()"),
        "priority tokens must be priceable to influence TVL prioritization"
    );
    assert!(
        scanner.contains("HIGH_VALUE_PRIORITY_TOKENS")
            && scanner.contains("Ignoring unpriced HIGH_VALUE_PRIORITY_TOKENS entry"),
        "custom priority tokens must be validated against pricing overrides"
    );
}
