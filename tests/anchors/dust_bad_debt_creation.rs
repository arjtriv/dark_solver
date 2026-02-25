use std::fs;

#[test]
fn test_dust_bad_debt_objective_is_wired_and_unprofitable_liquidation_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/dust_debt.rs")
        .expect("src/protocols/dust_debt.rs must be readable for dust bad-debt protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct DustBadDebtCreationObjective"),
        "solver must expose DustBadDebtCreationObjective"
    );
    assert!(
        objective_source.contains("build_dust_bad_debt_steps"),
        "dust bad-debt objective must build bounded exploit steps"
    );
    assert!(
        protocol_source.contains("known_dust_bad_debt_selectors"),
        "dust bad-debt protocol helper must expose selector seeds"
    );
    assert!(
        protocol_source.contains("liquidation_is_unprofitable"),
        "dust bad-debt protocol helper must enforce liquidation-unprofitability gate"
    );
    assert!(
        catalog_source.contains("DustBadDebtCreationObjective"),
        "objective catalog must include DustBadDebtCreationObjective"
    );
}
