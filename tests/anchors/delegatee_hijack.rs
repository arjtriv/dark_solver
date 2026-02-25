use std::fs;

#[test]
fn test_delegatee_hijack_objective_is_wired_and_auth_gap_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/governance.rs")
        .expect("src/protocols/governance.rs must be readable for delegatee-hijack protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct DelegateeHijackObjective"),
        "solver must expose DelegateeHijackObjective"
    );
    assert!(
        objective_source.contains("build_delegatee_hijack_steps"),
        "delegatee-hijack objective must build bounded exploit steps"
    );
    assert!(
        objective_source.contains("has_delegatee_hijack_pattern(bytecode)"),
        "delegatee-hijack objective must gate on delegate auth-gap bytecode pattern"
    );
    assert!(
        protocol_source.contains("unauthorized_delegate_to_attacker"),
        "governance protocol helper must model non-owner delegate-to-attacker predicate"
    );
    assert!(
        catalog_source.contains("DelegateeHijackObjective"),
        "objective catalog must include DelegateeHijackObjective"
    );
}
