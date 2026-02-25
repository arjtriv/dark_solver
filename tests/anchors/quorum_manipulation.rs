use std::fs;

#[test]
fn test_quorum_manipulation_objective_is_wired_and_supply_ratio_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/governance.rs").expect(
        "src/protocols/governance.rs must be readable for quorum-manipulation protocol audit",
    );
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct QuorumManipulationObjective"),
        "solver must expose QuorumManipulationObjective"
    );
    assert!(
        objective_source.contains("build_quorum_manipulation_steps"),
        "quorum-manipulation objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_quorum_manipulation_pattern(bytecode)"),
        "quorum-manipulation objective must gate on dynamic quorum-bytecode surface"
    );
    assert!(
        protocol_source.contains("quorum_ratio_satisfied_after_mint"),
        "governance protocol helper must model post-mint quorum ratio satisfiability"
    );
    assert!(
        catalog_source.contains("QuorumManipulationObjective"),
        "objective catalog must include QuorumManipulationObjective"
    );
}
