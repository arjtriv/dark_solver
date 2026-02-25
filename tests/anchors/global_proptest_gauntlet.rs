use std::fs;
use std::path::Path;

#[test]
fn test_global_proptest_gauntlet_scaffold_exists() {
    let entry = Path::new("tests/proptests.rs");
    let suite = Path::new("tests/proptests/protocols_gauntlet.rs");

    assert!(entry.exists(), "missing tests/proptests.rs entry point");
    assert!(
        suite.exists(),
        "missing tests/proptests/protocols_gauntlet.rs suite"
    );

    let content = fs::read_to_string(suite).unwrap_or_default();
    assert!(
        content.contains("const SAMPLES: usize = 10_000"),
        "gauntlet must run a 10,000-sample campaign"
    );
    assert!(
        content.contains("protocol_public_function_inventory_is_complete"),
        "gauntlet must lock protocol function inventory"
    );
    assert!(
        content.contains("src/protocols/uniswap_v3.rs:get_amount_out"),
        "gauntlet inventory missing uniswap_v3::get_amount_out"
    );
    assert!(
        content.contains("src/protocols/flash_loan/mod.rs:get_default_providers"),
        "gauntlet inventory missing flash_loan::get_default_providers"
    );
}
