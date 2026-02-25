use std::fs;

#[test]
fn test_collateral_factor_ltv_lag_objective_is_wired_and_lending_math_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let lending_source = fs::read_to_string("src/protocols/lending.rs")
        .expect("src/protocols/lending.rs must be readable for LTV-lag protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct CollateralFactorLtvLagObjective"),
        "solver must expose CollateralFactorLtvLagObjective"
    );
    assert!(
        objective_source.contains("collateral_factor_lag_violation"),
        "LTV-lag objective must enforce stale-oracle versus shocked-collateral lag predicate"
    );
    assert!(
        lending_source.contains("known_ltv_lag_selectors"),
        "lending protocol helper must expose known_ltv_lag_selectors"
    );
    assert!(
        lending_source.contains("value_after_bps_drop"),
        "lending protocol helper must model collateral shock through value_after_bps_drop"
    );
    assert!(
        catalog_source.contains("CollateralFactorLtvLagObjective"),
        "objective catalog must include CollateralFactorLtvLagObjective"
    );
}
