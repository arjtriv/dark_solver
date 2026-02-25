use std::fs;

#[test]
fn test_symbolic_fuzzing_objective_is_wired_and_thresholded() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct SymbolicFuzzingObjective"),
        "solver must expose SymbolicFuzzingObjective"
    );
    assert!(
        objective_source.contains("SYMBOLIC_FUZZ_STORAGE_WRITE_THRESHOLD: usize = 5"),
        "symbolic fuzzing must enforce the >5 storage-write anomaly threshold"
    );
    assert!(
        objective_source.contains("symbolic_fuzz_token_print_threshold"),
        "symbolic fuzzing must define a canonical >1M token print threshold"
    );
    assert!(
        objective_source.contains("has_symbolic_fuzz_anomaly"),
        "symbolic fuzzing must gate reports through an explicit anomaly predicate"
    );
    assert!(
        catalog_source.contains("SymbolicFuzzingObjective"),
        "objective catalog must include SymbolicFuzzingObjective"
    );
}
