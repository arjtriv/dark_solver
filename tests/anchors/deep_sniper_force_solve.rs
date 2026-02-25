use std::fs;

#[test]
fn deep_sniper_uses_shared_objective_catalog() {
    let sniper_source =
        fs::read_to_string("src/bin/deep_sniper.rs").expect("deep_sniper source must be readable");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("objective catalog source must be readable");

    assert!(
        sniper_source.contains("use dark_solver::engine::objective_catalog::build_objectives;"),
        "deep_sniper must consume shared objective catalog"
    );
    assert!(
        sniper_source.contains("run_objectives_parallel"),
        "deep_sniper must execute objectives through parallel runner"
    );
    assert!(
        catalog_source.contains("pub fn build_objectives"),
        "shared objective catalog must export build_objectives"
    );
}
