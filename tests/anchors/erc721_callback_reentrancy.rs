use std::fs;

#[test]
fn test_erc721_callback_reentrancy_objective_is_wired_and_callback_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/nft_callbacks.rs").expect(
        "src/protocols/nft_callbacks.rs must be readable for erc721 callback protocol audit",
    );
    let heuristics_source = fs::read_to_string("src/solver/heuristics.rs")
        .expect("src/solver/heuristics.rs must be readable for callback selector heuristic audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct Erc721CallbackReentrancyObjective"),
        "solver must expose Erc721CallbackReentrancyObjective"
    );
    assert!(
        objective_source.contains("build_erc721_callback_reentrancy_steps"),
        "erc721 callback objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_erc721_callback_reentrancy_pattern(bytecode)"),
        "erc721 callback objective must gate on safeTransfer+callback bytecode surface"
    );
    assert!(
        protocol_source.contains("known_erc721_callback_reentrancy_selectors"),
        "nft callback protocol helper must expose erc721 callback selector seeds"
    );
    assert!(
        heuristics_source.contains("scan_for_nft_callback_selectors"),
        "heuristics must include safeTransferFrom callback selector injection"
    );
    assert!(
        catalog_source.contains("Erc721CallbackReentrancyObjective"),
        "objective catalog must include Erc721CallbackReentrancyObjective"
    );
}
