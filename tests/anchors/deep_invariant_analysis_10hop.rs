//! Anchor: deep invariant analysis objective is wired into the deep objective catalog.

use std::fs;
use std::path::Path;

#[test]
fn deep_invariant_analysis_objective_is_present_in_background_deep_objectives() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let catalog = fs::read_to_string(repo_root.join("src/engine/objective_catalog.rs"))
        .expect("src/engine/objective_catalog.rs must be readable for objective catalog audit");
    let objective =
        fs::read_to_string(repo_root.join("src/tactics/objectives/objectives_deep_analysis.rs"))
            .expect("deep analysis objective source must be readable for anchor audit");

    assert!(
        catalog.contains("build_background_deep_objectives")
            && catalog.contains("build_deep_objectives_internal")
            && catalog.contains("DeepInvariantAnalysisObjective"),
        "expected DeepInvariantAnalysisObjective to be wired via build_background_deep_objectives -> build_deep_objectives_internal"
    );
    assert!(
        objective.contains("Deep Invariant Analysis (10-Hop)"),
        "expected Deep Invariant Analysis (10-Hop) objective name to remain stable for allow/deny filters and telemetry"
    );
}
