use std::fs;

#[test]
fn l2_native_bridge_arbitrage_objective_is_wired() {
    let registry = fs::read_to_string("src/tactics/objectives/mod.rs")
        .expect("objective registry must be readable");
    assert!(
        registry.contains("objectives_l2_bridge_arbitrage.rs"),
        "objective registry must include L2 bridge arbitrage objective file"
    );

    let objective_source =
        fs::read_to_string("src/tactics/objectives/objectives_l2_bridge_arbitrage.rs")
            .expect("L2 bridge arbitrage objective source must exist");
    assert!(
        objective_source.contains("L2NativeBridgeArbitrageObjective"),
        "objective must define L2NativeBridgeArbitrageObjective"
    );
    assert!(
        objective_source.contains("root_non_unique"),
        "objective must check for non-unique root constraints (root lag binding)"
    );
    assert!(
        objective_source.contains("is_opstack_chain"),
        "objective must gate to OP-Stack chain IDs"
    );

    let catalog = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("objective catalog must be readable");
    assert!(
        catalog.contains("L2NativeBridgeArbitrageObjective"),
        "deep objective catalog must include L2 bridge arbitrage objective"
    );
    assert!(
        catalog.contains("build_deep_objectives_internal(\n            solver_rpc.clone(),\n            chain_id,"),
        "deep objective builder must thread chain_id into deep objectives"
    );
}
