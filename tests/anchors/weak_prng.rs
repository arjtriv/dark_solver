use std::fs;

#[test]
fn test_weak_prng_objective_is_wired_and_entropy_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/prng.rs")
        .expect("src/protocols/prng.rs must be readable for weak-prng protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct WeakPrngObjective"),
        "solver must expose WeakPrngObjective"
    );
    assert!(
        objective_source.contains("build_weak_prng_steps"),
        "weak-prng objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_weak_prng_pattern(bytecode)"),
        "weak-prng objective must gate execution on weak-entropy bytecode signals"
    );
    assert!(
        protocol_source.contains("next_block_timestamp_in_range"),
        "weak-prng protocol helper must constrain next-block timestamp range"
    );
    assert!(
        protocol_source.contains("wins_modulo"),
        "weak-prng protocol helper must enforce modulo win condition"
    );
    assert!(
        catalog_source.contains("WeakPrngObjective"),
        "objective catalog must include WeakPrngObjective"
    );
}
