//! Anchor Test: gauntlet catalog shape remains Top-100.

#[path = "../gauntlet/catalog.rs"]
mod gauntlet_catalog;

#[test]
fn test_gauntlet_catalog_has_100_cases() {
    let cases = gauntlet_catalog::top_100_historical_cases();
    assert_eq!(cases.len(), 100);
}
