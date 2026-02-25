use std::fs;

#[test]
fn test_taint_flow_storage_objective_is_wired_with_guard_check() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct TaintFlowStorageCorruptionObjective"),
        "solver must expose TaintFlowStorageCorruptionObjective"
    );
    assert!(
        objective_source.contains("key_depends_on_user_input"),
        "taint-flow objective must detect user-input dependence in storage keys"
    );
    assert!(
        objective_source.contains("trace_has_jumpi_guard"),
        "taint-flow objective must model JUMPI guard presence"
    );
    assert!(
        objective_source.contains("if has_guard {") && objective_source.contains("continue;"),
        "taint-flow objective must reject guarded paths and only report unguarded taint writes"
    );
    assert!(
        catalog_source.contains("TaintFlowStorageCorruptionObjective"),
        "objective catalog must include TaintFlowStorageCorruptionObjective"
    );
}
