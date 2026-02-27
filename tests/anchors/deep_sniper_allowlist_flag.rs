use std::fs;

#[test]
fn deep_sniper_allowlist_flag_stays_hooked_up() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(
        source.contains("--objective-allowlist") || source.contains("--allowlist"),
        "allowlist flag should stay in the public cli"
    );
    assert!(
        source.contains("OBJECTIVE_ALLOWLIST"),
        "allowlist flag should still feed the objective env"
    );
}
