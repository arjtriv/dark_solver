use std::fs;

#[test]
fn test_scanner_token_valuation_guards_are_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");

    assert!(
        scanner.contains("HIGH_VALUE_PRIORITY_TOKEN_PRICES_ETH_WEI")
            && scanner.contains("PROFIT_TOKEN_PRICES_ETH_WEI")
            && scanner.contains("scanner_price_overrides_eth_wei"),
        "scanner must support explicit token pricing overrides for priority/high-value valuation"
    );
    assert!(
        scanner.contains("HIGH_VALUE_PRIORITY_TOKEN_DECIMALS")
            && scanner.contains("PROFIT_TOKEN_DECIMALS")
            && scanner.contains("scanner_decimal_overrides"),
        "scanner must support explicit decimals overrides for priority/high-value valuation"
    );
    assert!(
        scanner.contains("is_known_six_decimal_stable")
            && scanner.contains("dAC17F958D2ee523a2206206994597C13D831ec7")
            && scanner.contains("6B175474E89094C44Da98b954EedeAC495271d0F"),
        "scanner must avoid hardcoding all stables to 6 decimals (USDT/DAI defaults must diverge)"
    );
}
