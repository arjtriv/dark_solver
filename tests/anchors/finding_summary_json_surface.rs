use std::fs;

#[test]
fn finding_summary_json_helpers_stay_in_core_types() {
    let source =
        fs::read_to_string("src/tactics/objectives/core.rs").expect("read objective core");
    assert!(
        source.contains("impl ExecuteIfStorageEq") && source.contains("to_summary_json"),
        "storage equality guards should keep json summaries"
    );
    assert!(
        source.contains("impl ExploitStep") && source.contains("impl ExploitParams"),
        "step and param summaries should stay available"
    );
}
