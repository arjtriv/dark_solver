use std::fs;

#[test]
fn test_read_only_reentrancy_objective_is_wired_and_stale_view_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/read_only_reentrancy.rs").expect(
        "src/protocols/read_only_reentrancy.rs must be readable for stale-view protocol audit",
    );
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct ReadOnlyReentrancyObjective"),
        "solver must expose ReadOnlyReentrancyObjective"
    );
    assert!(
        objective_source.contains("build_read_only_reentrancy_steps"),
        "read-only reentrancy objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_read_only_reentrancy_pattern(bytecode)"),
        "read-only reentrancy objective must gate on stale-view callback bytecode surface"
    );
    assert!(
        objective_source.contains("view_read_during_callback"),
        "read-only reentrancy objective must require callback-time view-read condition"
    );
    assert!(
        protocol_source.contains("stale_view_price_drift_exceeds_bps"),
        "stale-view protocol helper must model mid-execution vs post-execution drift gate"
    );
    assert!(
        catalog_source.contains("ReadOnlyReentrancyObjective"),
        "objective catalog must include ReadOnlyReentrancyObjective"
    );
}
