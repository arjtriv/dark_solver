use std::fs;

#[test]
fn deep_sniper_pin_block_flag_stays_visible() {
    let source = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    assert!(
        source.contains("--pin-block-number") || source.contains("--pin-block"),
        "pin-block flag should stay part of the public cli"
    );
    assert!(
        source.contains("FORKDB_PIN_BLOCK_NUMBER"),
        "pin-block flag should still wire through the forkdb env"
    );
}
