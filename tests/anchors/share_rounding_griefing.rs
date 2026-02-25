use std::fs;

#[test]
fn test_share_rounding_griefing_objective_is_wired_and_roundtrip_gain_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/erc4626.rs")
        .expect("src/protocols/erc4626.rs must be readable for share-rounding protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct ShareRoundingGriefingObjective"),
        "solver must expose ShareRoundingGriefingObjective"
    );
    assert!(
        objective_source.contains("build_share_rounding_griefing_steps"),
        "share-rounding objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_share_rounding_griefing_pattern(bytecode)"),
        "share-rounding objective must gate on erc4626 roundtrip bytecode surface"
    );
    assert!(
        objective_source.contains("share_roundtrip_leaks_assets"),
        "share-rounding objective must enforce post-roundtrip attacker asset gain predicate"
    );
    assert!(
        protocol_source.contains("share_roundtrip_leaks_assets"),
        "erc4626 protocol helper must model roundtrip leak predicate"
    );
    assert!(
        catalog_source.contains("ShareRoundingGriefingObjective"),
        "objective catalog must include ShareRoundingGriefingObjective"
    );
}
