use std::fs;

#[test]
fn test_gambling_contract_scanner_objective_is_wired_and_entropy_payout_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/prng.rs")
        .expect("src/protocols/prng.rs must be readable for gambling-scanner protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct GamblingContractScannerObjective"),
        "solver must expose GamblingContractScannerObjective"
    );
    assert!(
        objective_source.contains("build_gambling_contract_scanner_steps"),
        "gambling-scanner objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_gambling_contract_pattern(bytecode)"),
        "gambling-scanner objective must gate on entropy-plus-payout bytecode pattern"
    );
    assert!(
        protocol_source.contains("known_gambling_scanner_selectors"),
        "prng protocol helper must provide gambling scanner selector seeds"
    );
    assert!(
        protocol_source.contains("has_gambling_contract_pattern"),
        "prng protocol helper must expose gambling contract bytecode detection"
    );
    assert!(
        catalog_source.contains("GamblingContractScannerObjective"),
        "objective catalog must include GamblingContractScannerObjective"
    );
}
