use std::fs;

#[test]
fn test_erc721_approval_hijack_objective_is_wired_and_approval_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/nft_callbacks.rs").expect(
        "src/protocols/nft_callbacks.rs must be readable for erc721 approval protocol audit",
    );
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct Erc721ApprovalHijackObjective"),
        "solver must expose Erc721ApprovalHijackObjective"
    );
    assert!(
        objective_source.contains("build_erc721_approval_hijack_steps"),
        "erc721 approval objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_erc721_approval_hijack_pattern(bytecode)"),
        "erc721 approval objective must gate on callback-plus-approval bytecode surface"
    );
    assert!(
        protocol_source.contains("approval_hijack_succeeds"),
        "nft callback protocol helper must model post-callback approval hijack predicate"
    );
    assert!(
        catalog_source.contains("Erc721ApprovalHijackObjective"),
        "objective catalog must include Erc721ApprovalHijackObjective"
    );
}
