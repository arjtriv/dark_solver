use std::fs;

#[test]
fn test_pinned_block_fork_replay_is_supported_in_shadow_verifier() {
    let verifier = fs::read_to_string("src/executor/verifier.rs")
        .expect("src/executor/verifier.rs must be readable for pinned-block replay audit");
    assert!(
        verifier.contains("pinned_block: Option<u64>"),
        "verifier must accept an explicit pinned_block option"
    );
    assert!(
        verifier.contains("ForkDB::with_block_number"),
        "verifier must construct a pinned ForkDB when pinned_block is present"
    );

    let exec = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for pinned-block replay audit");
    assert!(
        exec.contains("Some(target_solve_block)"),
        "executor must run pinned-block replay at solve block before private submission"
    );
}
