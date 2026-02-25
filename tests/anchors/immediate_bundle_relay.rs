//! Anchor: Immediate bundle relay wiring exists (skip duplicate local replay when already verified).

#[test]
fn immediate_bundle_relay_is_wired_via_verified_shadow_report() {
    let executor_source = include_str!("../../src/executor/mod.rs");
    assert!(
        executor_source.contains("verified_shadow_report"),
        "executor context must support verified shadow replay injection"
    );

    let main_source = include_str!("../../src/main.rs");
    assert!(
        main_source.contains("IMMEDIATE_BUNDLE_RELAY_ENABLED"),
        "main must expose an env toggle for immediate bundle relay"
    );
}
