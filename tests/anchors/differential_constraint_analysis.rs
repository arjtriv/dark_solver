use std::fs;

#[test]
fn test_differential_constraint_objective_is_wired_and_formal() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct DifferentialConstraintObjective"),
        "solver must expose DifferentialConstraintObjective"
    );
    assert!(
        objective_source.contains("has_differential_constraint_gap"),
        "differential analysis must include explicit implication-gap proof gate"
    );
    assert!(
        objective_source.contains("constraint_implies"),
        "differential analysis must model implication checks over solver constraints"
    );
    assert!(
        objective_source.contains("same_slot_possible"),
        "differential analysis must require satisfiable same-slot write aliasing"
    );
    assert!(
        catalog_source.contains("DifferentialConstraintObjective"),
        "objective catalog must include DifferentialConstraintObjective"
    );
}
