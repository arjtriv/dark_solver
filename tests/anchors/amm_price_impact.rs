use std::fs;

#[test]
fn test_amm_price_impact_objective_is_wired_and_cost_profit_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/amm_price_impact.rs")
        .expect("src/protocols/amm_price_impact.rs must be readable for AMM price-impact audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct AmmPriceImpactObjective"),
        "solver must expose AmmPriceImpactObjective"
    );
    assert!(
        objective_source.contains("build_amm_price_impact_steps"),
        "AMM price-impact objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("liquidation_profit.bvugt(&attack_cost)"),
        "AMM price-impact objective must enforce attack_cost < liquidation_profit"
    );
    assert!(
        protocol_source.contains("sqrt_price_drop_exceeds_bps"),
        "AMM price-impact protocol helper must enforce bps-denominated price-impact gate"
    );
    assert!(
        protocol_source.contains("sqrt_price_x96_after_input"),
        "AMM price-impact protocol helper must derive post-swap sqrt price from depth"
    );
    assert!(
        catalog_source.contains("AmmPriceImpactObjective"),
        "objective catalog must include AmmPriceImpactObjective"
    );
}
