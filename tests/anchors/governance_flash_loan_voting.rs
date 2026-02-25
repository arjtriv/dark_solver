use std::fs;

#[test]
fn test_governance_flash_loan_voting_objective_is_wired_and_quorum_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/governance.rs")
        .expect("src/protocols/governance.rs must be readable for governance protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct GovernanceExploitObjective"),
        "solver must expose GovernanceExploitObjective"
    );
    assert!(
        objective_source.contains("build_governance_flash_vote_steps"),
        "governance objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_flash_loan_governance_pattern(bytecode)"),
        "governance objective must gate on flash-loan-vote bytecode pattern"
    );
    assert!(
        protocol_source.contains("flash_loan_meets_quorum"),
        "governance protocol helper must enforce flash-loan quorum gate"
    );
    assert!(
        protocol_source.contains("proposal_transfers_treasury"),
        "governance protocol helper must enforce treasury-drain proposal predicate"
    );
    assert!(
        catalog_source.contains("GovernanceExploitObjective"),
        "objective catalog must include GovernanceExploitObjective"
    );
}
