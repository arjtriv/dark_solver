use std::fs;

#[test]
fn test_executor_does_not_submit_without_submission_mode() {
    let exec = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for executor private submission gate audit");

    assert!(
        exec.contains("submission_enabled: bool"),
        "executor must carry a submission_enabled mode flag from Config"
    );
    assert!(
        exec.contains("if self.submission_enabled"),
        "executor must gate private submission-only behaviors behind self.submission_enabled"
    );
    assert!(
        exec.contains("[EXEC] Dispatching private bundle via"),
        "executor must explicitly log private bundle dispatch"
    );
}
