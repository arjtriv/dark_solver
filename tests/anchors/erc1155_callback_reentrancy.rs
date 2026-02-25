use std::fs;

#[test]
fn test_erc1155_callback_reentrancy_objective_is_wired_and_callback_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/nft_callbacks.rs").expect(
        "src/protocols/nft_callbacks.rs must be readable for erc1155 callback protocol audit",
    );
    let heuristics_source = fs::read_to_string("src/solver/heuristics.rs")
        .expect("src/solver/heuristics.rs must be readable for callback selector heuristic audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct Erc1155CallbackReentrancyObjective"),
        "solver must expose Erc1155CallbackReentrancyObjective"
    );
    assert!(
        objective_source.contains("build_erc1155_callback_reentrancy_steps"),
        "erc1155 callback objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_erc1155_callback_reentrancy_pattern(bytecode)"),
        "erc1155 callback objective must gate on safeTransfer/safeBatchTransfer callback surface"
    );
    assert!(
        protocol_source.contains("known_erc1155_callback_reentrancy_selectors"),
        "nft callback protocol helper must expose erc1155 callback selector seeds"
    );
    assert!(
        heuristics_source.contains("onERC1155BatchReceived"),
        "heuristics must inject erc1155 callback selectors for safe transfer surfaces"
    );
    assert!(
        catalog_source.contains("Erc1155CallbackReentrancyObjective"),
        "objective catalog must include Erc1155CallbackReentrancyObjective"
    );
}
