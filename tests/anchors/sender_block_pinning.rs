use std::fs;

#[test]
fn test_sender_block_pinning_is_wired() {
    let pinning = fs::read_to_string("src/executor/pinning_anchor.rs")
        .expect("src/executor/pinning_anchor.rs must be readable");
    let verifier = fs::read_to_string("src/executor/verifier.rs")
        .expect("src/executor/verifier.rs must be readable");
    let exec =
        fs::read_to_string("src/executor/mod.rs").expect("src/executor/mod.rs must be readable");

    assert!(
        pinning.contains("PINNING_ANCHOR_ADDRESS")
            && pinning.contains("PINNING_ANCHOR_ENABLED")
            && pinning.contains("PINNING_ANCHOR_STRICT_BLOCK_MATCH")
            && pinning.contains("executePinned"),
        "pinning anchor must be configurable and encode executePinned(expectedOrigin, expectedBlock, target, data)"
    );

    assert!(
        verifier.contains("replay_path_at_block_with_env")
            && verifier.contains("replay_path_with_env")
            && verifier.contains("env_block_number"),
        "verifier must support explicit env block numbers for pinned payload simulation"
    );

    assert!(
        exec.contains("pinning_anchor::pinning_anchor_active()")
            && exec.contains("pinning_anchor::maybe_wrap_with_pinning_anchor")
            && exec.contains("intended_env_block"),
        "executor must wire pinning anchor wrapping and thread intended env block through replay gates"
    );
}
