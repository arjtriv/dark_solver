use std::fs;

#[test]
fn test_scanner_capital_profiler_token_cache_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("fn build_capital_profiler_tokens("),
        "Scanner should centralize capital-profiler token construction."
    );
    assert!(
        source.contains("if chain_config.weth != Address::ZERO"),
        "Capital profiler token builder must filter zero WETH entries."
    );
    assert!(
        source.contains("static CACHE: OnceLock<Mutex<HashMap<u64, Vec<Address>>>>"),
        "Capital profiler token list should be cached per chain id."
    );
}
