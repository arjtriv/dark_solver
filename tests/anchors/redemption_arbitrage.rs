use std::fs;

#[test]
fn test_redemption_arbitrage_objective_is_wired_and_peg_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/redemption.rs")
        .expect("src/protocols/redemption.rs must be readable for redemption-arbitrage audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct RedemptionArbitrageObjective"),
        "solver must expose RedemptionArbitrageObjective"
    );
    assert!(
        objective_source.contains("build_redemption_arbitrage_steps"),
        "redemption-arbitrage objective must build bounded exploit steps"
    );
    assert!(
        protocol_source.contains("known_redemption_selectors"),
        "redemption protocol helper must expose known redemption selectors"
    );
    assert!(
        protocol_source.contains("redemption_arb_exceeds_bps"),
        "redemption protocol helper must enforce spread threshold constraints"
    );
    assert!(
        catalog_source.contains("RedemptionArbitrageObjective"),
        "objective catalog must include RedemptionArbitrageObjective"
    );
}
