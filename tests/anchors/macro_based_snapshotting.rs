use std::fs;

#[test]
fn test_macro_based_snapshotting_schema_exists_and_covers_symbolic_machine() {
    let state_source = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for snapshot macro audit");

    assert!(
        state_source.contains("macro_rules! symbolic_snapshot_schema"),
        "snapshot schema macro must exist"
    );
    assert!(
        state_source.contains("symbolic_snapshot_schema! {"),
        "SymbolicMachine snapshot/restore must be generated from the schema macro"
    );
    assert!(
        state_source.contains("pub struct Snapshot<'ctx>"),
        "Snapshot struct must be macro-generated (not hand-written elsewhere)"
    );
    assert!(
        state_source.contains("fn assert_snapshot_field_coverage"),
        "snapshot code must enforce compile-time field coverage to prevent state pollution"
    );
    assert!(
        state_source.contains("dead_end_pcs: _"),
        "coverage assertion must destructure SymbolicMachine fields (audit sentinel)"
    );
}
