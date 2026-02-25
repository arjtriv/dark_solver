use std::fs;

#[test]
fn test_chainlink_vrf_timing_attack_objective_is_wired_and_timing_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/chainlink_vrf.rs")
        .expect("src/protocols/chainlink_vrf.rs must be readable for vrf protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct ChainlinkVrfTimingAttackObjective"),
        "solver must expose ChainlinkVrfTimingAttackObjective"
    );
    assert!(
        objective_source.contains("build_chainlink_vrf_timing_steps"),
        "vrf-timing objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_vrf_timing_pattern(bytecode)"),
        "vrf-timing objective must gate on fulfill-plus-claim bytecode pattern"
    );
    assert!(
        protocol_source.contains("same_block_claim_window"),
        "vrf protocol helper must constrain same-block claim window"
    );
    assert!(
        protocol_source.contains("vrf_claim_wins"),
        "vrf protocol helper must enforce modulo win condition"
    );
    assert!(
        catalog_source.contains("ChainlinkVrfTimingAttackObjective"),
        "objective catalog must include ChainlinkVrfTimingAttackObjective"
    );
}
