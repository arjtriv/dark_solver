use std::fs;

#[test]
fn test_state_transition_cycle_objective_uses_tarjan_and_cycle_gate() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct StateTransitionCycleObjective"),
        "solver must expose StateTransitionCycleObjective"
    );
    assert!(
        objective_source.contains("fn tarjan_scc"),
        "STG cycle detection must use Tarjan SCC decomposition"
    );
    assert!(
        objective_source.contains("STG_UNPRIVILEGED")
            && objective_source.contains("STG_PRIVILEGED"),
        "STG cycle detection must model unprivileged/privileged state nodes explicitly"
    );
    assert!(
        objective_source.contains("has_positive_attacker_receipt"),
        "cycle detection must require positive attacker inflow before reporting"
    );
    assert!(
        catalog_source.contains("StateTransitionCycleObjective"),
        "objective catalog must include StateTransitionCycleObjective"
    );
}
