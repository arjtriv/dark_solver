use std::fs;

#[test]
fn shadow_replay_cli_surface_stays_public() {
    let source = fs::read_to_string("src/bin/shadow_replay.rs").expect("read shadow_replay.rs");
    assert!(
        source.contains("--rpc-url") && source.contains("--chain-id"),
        "shadow_replay should keep named connection flags"
    );
    assert!(
        source.contains("--address") && source.contains("--block-number"),
        "shadow_replay should keep named target flags"
    );
    assert!(
        source.contains("--json"),
        "shadow_replay should keep json output available"
    );
}
