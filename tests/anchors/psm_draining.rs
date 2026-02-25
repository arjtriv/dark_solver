use std::fs;

#[test]
fn test_psm_draining_objective_is_wired_and_uses_ratio_gate() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/psm.rs")
        .expect("src/protocols/psm.rs must be readable for PSM draining audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct PsmDrainingObjective"),
        "solver must expose PsmDrainingObjective"
    );
    assert!(
        objective_source.contains("has_psm_drain_signal"),
        "psm draining must gate on explicit drain signal checks"
    );
    assert!(
        protocol_source.contains("psm_drain_ratio_exceeds_bps"),
        "psm protocol helper must enforce ratio-based drain detection"
    );
    assert!(
        catalog_source.contains("PsmDrainingObjective"),
        "objective catalog must include PsmDrainingObjective"
    );
}
