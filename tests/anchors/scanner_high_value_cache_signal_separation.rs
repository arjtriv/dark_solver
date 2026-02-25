use std::fs;

#[test]
fn test_scanner_high_value_cache_signal_separation_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");

    assert!(
        source.contains("fn structural_hubris_cache()"),
        "Scanner must keep structural-hubris hints in a dedicated cache."
    );
    assert!(
        source.contains("remember_structural_hubris(address, now);"),
        "Dust structural-hubris path must write to dedicated cache."
    );

    let dust_start = source
        .find("async fn contract_meets_dust_liquidity")
        .expect("dust liquidity function start");
    let hv_start = source
        .find("pub async fn contract_meets_high_value_tvl")
        .expect("high value tvl function start");
    let dust_section = &source[dust_start..hv_start];

    assert!(
        !dust_section.contains("high_value_cache().lock()"),
        "Dust liquidity path must not mutate high-value TVL decision cache."
    );
}
