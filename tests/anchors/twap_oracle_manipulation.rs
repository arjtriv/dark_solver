use std::fs;

#[test]
fn test_twap_oracle_objective_is_wired_and_multiblock() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct TwapOracleManipulationObjective"),
        "solver must expose TwapOracleManipulationObjective"
    );
    assert!(
        objective_source.contains("build_block_offsets"),
        "TWAP objective must assign multi-block offsets to steps"
    );
    assert!(
        objective_source.contains("discover_oracle_deps"),
        "TWAP objective must require oracle dependency discovery"
    );
    assert!(
        catalog_source.contains("TwapOracleManipulationObjective"),
        "objective catalog must include TwapOracleManipulationObjective"
    );
}
