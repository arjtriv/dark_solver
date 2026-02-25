use std::fs;

#[test]
fn test_polynomial_invariant_objective_is_wired_with_violation_gate() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct PolynomialInvariantObjective"),
        "solver must expose PolynomialInvariantObjective"
    );
    assert!(
        objective_source.contains("read_storage_slot_word"),
        "polynomial objective must read storage-slot words for invariant derivation"
    );
    assert!(
        objective_source.contains("selected_slot_touched_constraint")
            && objective_source.contains("solver.assert(&touched_slot_a)")
            && objective_source.contains("solver.assert(&touched_slot_b)"),
        "polynomial objective must require candidate-slot touch before reporting"
    );
    assert!(
        objective_source.contains("has_polynomial_invariant_violation"),
        "polynomial objective must enforce explicit x*y drop violation check"
    );
    assert!(
        catalog_source.contains("PolynomialInvariantObjective"),
        "objective catalog must include PolynomialInvariantObjective"
    );
}
