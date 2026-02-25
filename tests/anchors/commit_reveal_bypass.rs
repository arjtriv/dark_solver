use std::fs;

#[test]
fn test_commit_reveal_bypass_objective_is_wired_and_seed_leak_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/commit_reveal.rs")
        .expect("src/protocols/commit_reveal.rs must be readable for commit-reveal protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct CommitRevealBypassObjective"),
        "solver must expose CommitRevealBypassObjective"
    );
    assert!(
        objective_source.contains("build_commit_reveal_bypass_steps"),
        "commit-reveal objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_commit_reveal_pattern(bytecode)"),
        "commit-reveal objective must gate on commit/reveal bytecode pattern"
    );
    assert!(
        protocol_source.contains("hash_matches_preimage"),
        "commit-reveal protocol helper must model leaked-seed hash consistency"
    );
    assert!(
        protocol_source.contains("reveal_outcome_wins"),
        "commit-reveal protocol helper must enforce modulo win condition for reveal"
    );
    assert!(
        catalog_source.contains("CommitRevealBypassObjective"),
        "objective catalog must include CommitRevealBypassObjective"
    );
}
