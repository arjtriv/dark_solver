use std::fs;

#[test]
fn deep_sniper_objective_status_output_is_still_wired() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(
        source.contains("--objective-status"),
        "objective-status flag should stay on the cli"
    );
    assert!(
        source.contains("run_objectives_parallel_detailed"),
        "objective-status mode should still use the detailed runner"
    );
}
