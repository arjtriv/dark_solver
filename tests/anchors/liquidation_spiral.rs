use std::fs;

#[test]
fn test_liquidation_spiral_objective_is_wired_and_drop_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct LiquidationSpiralObjective"),
        "solver must expose LiquidationSpiralObjective"
    );
    assert!(
        objective_source.contains("reserve_drop_exceeds_bps"),
        "liquidation spiral must enforce a reserve-drop ratio gate"
    );
    assert!(
        objective_source.contains("execute_liquidation_spiral_trace"),
        "liquidation spiral must extract pre/post reserve slot deltas"
    );
    assert!(
        catalog_source.contains("LiquidationSpiralObjective"),
        "objective catalog must include LiquidationSpiralObjective"
    );
}
