use std::fs;

#[test]
fn test_coinbase_bribe_direct_path_is_wired_in_executor() {
    let source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for coinbase bribe anchor");

    assert!(
        source.contains("ICoinbaseBribe")
            && source.contains("append_coinbase_bribe_transaction")
            && source.contains("load_coinbase_bribe_contract"),
        "executor must include contract-based direct coinbase bribe transaction wiring"
    );
    assert!(
        source.contains("COINBASE_BRIBE_ENABLED")
            && source.contains("COINBASE_BRIBE_THRESHOLD_WEI")
            && source.contains("COINBASE_BRIBE_BPS"),
        "coinbase bribe gate must be configurable and threshold-gated"
    );
    assert!(
        source.contains("is_coinbase_bribe_builder_url")
            && source.contains("has_coinbase_bribe_route")
            && source.contains("self.coinbase_bribe_route_enabled"),
        "direct coinbase bribes must be scoped to known bribe-capable builder routes"
    );
}
