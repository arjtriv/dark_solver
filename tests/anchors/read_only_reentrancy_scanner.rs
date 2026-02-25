use std::fs;

#[test]
fn test_read_only_reentrancy_scanner_objective_is_wired_and_staticcall_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/read_only_reentrancy.rs")
        .expect("src/protocols/read_only_reentrancy.rs must be readable for read-only scanner protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct ReadOnlyReentrancyScannerObjective"),
        "solver must expose ReadOnlyReentrancyScannerObjective"
    );
    assert!(
        objective_source.contains("build_read_only_reentrancy_scanner_steps"),
        "read-only scanner objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_read_only_reentrancy_scanner_pattern"),
        "read-only scanner objective must gate on staticcall+callback scanner pattern"
    );
    assert!(
        objective_source.contains("staticcall_result_used_in_decision"),
        "read-only scanner objective must require staticcall-result decision dependency"
    );
    assert!(
        protocol_source.contains("known_read_only_reentrancy_scanner_selectors"),
        "read-only protocol helper must expose scanner selector seeds"
    );
    assert!(
        catalog_source.contains("ReadOnlyReentrancyScannerObjective"),
        "objective catalog must include ReadOnlyReentrancyScannerObjective"
    );
}
