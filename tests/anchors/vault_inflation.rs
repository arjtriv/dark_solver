use std::fs;

#[test]
fn test_vault_inflation_objective_is_wired_and_first_depositor_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/erc4626.rs")
        .expect("src/protocols/erc4626.rs must be readable for vault-inflation protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct VaultInflationObjective"),
        "solver must expose VaultInflationObjective"
    );
    assert!(
        objective_source.contains("build_vault_inflation_steps"),
        "vault-inflation objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_vault_inflation_pattern(bytecode)"),
        "vault-inflation objective must gate on erc4626 inflation bytecode surface"
    );
    assert!(
        objective_source.contains("first_depositor_inflation_drainable"),
        "vault-inflation objective must enforce first-depositor drainability predicate"
    );
    assert!(
        protocol_source.contains("first_depositor_inflation_drainable"),
        "erc4626 protocol helper must model first-depositor donation inflation constraints"
    );
    assert!(
        catalog_source.contains("VaultInflationObjective"),
        "objective catalog must include VaultInflationObjective"
    );
}
