use std::fs;

#[test]
fn test_erc721_mint_callback_drain_objective_is_wired_and_supply_bypass_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/nft_callbacks.rs").expect(
        "src/protocols/nft_callbacks.rs must be readable for erc721 mint callback protocol audit",
    );
    let heuristics_source = fs::read_to_string("src/solver/heuristics.rs")
        .expect("src/solver/heuristics.rs must be readable for callback selector heuristic audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct Erc721MintCallbackDrainObjective"),
        "solver must expose Erc721MintCallbackDrainObjective"
    );
    assert!(
        objective_source.contains("build_erc721_mint_callback_drain_steps"),
        "erc721 mint callback objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_erc721_mint_callback_drain_pattern(bytecode)"),
        "erc721 mint callback objective must gate on safeMint+callback bytecode surface"
    );
    assert!(
        objective_source.contains("total_minted_post.bvugt(&max_supply)"),
        "erc721 mint callback objective must enforce post-callback supply-cap bypass gate"
    );
    assert!(
        protocol_source.contains("known_erc721_mint_callback_drain_selectors"),
        "nft callback protocol helper must expose erc721 mint callback selector seeds"
    );
    assert!(
        heuristics_source.contains("safeMint(address,uint256)"),
        "heuristics must include safeMint callback selector injection"
    );
    assert!(
        catalog_source.contains("Erc721MintCallbackDrainObjective"),
        "objective catalog must include Erc721MintCallbackDrainObjective"
    );
}
