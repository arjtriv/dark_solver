use std::fs;

#[test]
fn deep_sniper_filter_bounds_are_still_public() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(
        source.contains("OBJECTIVE_DENYLIST"),
        "denylist wiring should stay exposed"
    );
    assert!(
        source.contains("OBJECTIVE_MAX_PER_TARGET"),
        "per-target objective caps should stay exposed"
    );
}
