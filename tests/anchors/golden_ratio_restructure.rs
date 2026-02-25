use std::fs;

#[test]
fn test_golden_ratio_restructure_namespaces_are_exposed_and_wired() {
    let lib_source = fs::read_to_string("src/lib.rs")
        .expect("src/lib.rs must be readable for golden-ratio namespace audit");
    let core_source = fs::read_to_string("src/core/mod.rs")
        .expect("src/core/mod.rs must be readable for core namespace audit");
    let knowledge_source = fs::read_to_string("src/knowledge/mod.rs")
        .expect("src/knowledge/mod.rs must be readable for knowledge namespace audit");
    let tactics_source = fs::read_to_string("src/tactics/mod.rs")
        .expect("src/tactics/mod.rs must be readable for tactics namespace audit");
    let engine_source = fs::read_to_string("src/engine/mod.rs")
        .expect("src/engine/mod.rs must be readable for engine namespace audit");
    let hand_source = fs::read_to_string("src/hand/mod.rs")
        .expect("src/hand/mod.rs must be readable for hand namespace audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for runtime wiring audit");

    for namespace in [
        "pub mod core;",
        "pub mod knowledge;",
        "pub mod tactics;",
        "pub mod engine;",
        "pub mod hand;",
    ] {
        assert!(
            lib_source.contains(namespace),
            "lib.rs must expose `{namespace}` in golden-ratio namespace map"
        );
    }

    assert!(core_source.contains("pub use crate::symbolic::engine;"));
    assert!(knowledge_source.contains("pub use crate::protocols::erc4626;"));
    assert!(tactics_source.contains("pub use crate::strategies::guided_storage;"));
    assert!(engine_source.contains("pub use crate::solver::objectives;"));
    assert!(hand_source.contains("pub use crate::executor::verifier;"));
    assert!(
        main_source.contains("dark_solver::engine::objective_catalog::"),
        "runtime objective wiring must use engine objective_catalog namespace after golden-ratio restructure"
    );
}
