use std::fs;

#[test]
fn groth16_verifier_audit_is_wired() {
    let protocols_mod =
        fs::read_to_string("src/protocols/mod.rs").expect("protocols mod must be readable");
    assert!(
        protocols_mod.contains("pub mod groth16;"),
        "protocols must export groth16 module"
    );

    let groth16 =
        fs::read_to_string("src/protocols/groth16.rs").expect("groth16 protocol module must exist");
    assert!(
        groth16.contains("audit_groth16_verifier"),
        "groth16 module must expose audit function"
    );
    assert!(
        groth16.contains("MissingPublicInputBinding"),
        "groth16 audit must define missing public input binding issue"
    );

    let registry = fs::read_to_string("src/tactics/objectives/mod.rs")
        .expect("objective registry must be readable");
    assert!(
        registry.contains("objectives_groth16_audit.rs"),
        "objective registry must include groth16 audit objective"
    );

    let catalog = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("objective catalog must be readable");
    assert!(
        catalog.contains("Groth16VerifierAuditObjective"),
        "deep objective catalog must include groth16 verifier audit objective"
    );
}
