use std::fs;
use std::path::Path;

#[test]
fn test_modular_tactics_registry_is_wired_with_solver_compat_bridge() {
    let tactics_mod = Path::new("src/tactics/objectives/mod.rs");
    let solver_bridge = Path::new("src/solver/objectives.rs");

    assert!(
        tactics_mod.exists(),
        "src/tactics/objectives/mod.rs must exist for modular registry"
    );
    assert!(
        solver_bridge.exists(),
        "src/solver/objectives.rs compatibility bridge must exist"
    );

    let tactics_source = fs::read_to_string(tactics_mod).unwrap_or_default();
    let solver_source = fs::read_to_string(solver_bridge).unwrap_or_default();

    assert!(
        tactics_source.contains("include!(\"core.rs\")")
            && tactics_source.contains("include!(\"objectives_lending_oracle.rs\")")
            && tactics_source.contains("include!(\"objectives_credit_amm.rs\")"),
        "tactics objective registry must include sharded objective modules"
    );

    assert!(
        solver_source.contains("pub use crate::tactics::objectives::*;"),
        "solver objectives module must remain a compatibility re-export bridge"
    );
}
