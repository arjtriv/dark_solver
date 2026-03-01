use std::fs;

#[test]
fn deep_sniper_timeout_flag_stays_hooked_up() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(
        source.contains("--objective-timeout-ms"),
        "objective timeout flag should stay public"
    );
    assert!(
        source.contains("args.objective_timeout_ms"),
        "timeout flag should still flow into the detailed runner"
    );
}
