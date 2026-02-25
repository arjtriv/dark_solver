use std::fs;

#[test]
fn test_payload_polymorphism_is_wired() {
    let hardening = fs::read_to_string("src/executor/payload_hardening.rs")
        .expect("src/executor/payload_hardening.rs must be readable");

    assert!(
        hardening.contains("PAYLOAD_POLYMORPHISM_ENABLED")
            && hardening.contains("PAYLOAD_POLYMORPHIC_MAX_TAIL_BYTES")
            && hardening.contains("append_polymorphic_tail_padding")
            && hardening.contains("maybe_reorder_independent_steps")
            && hardening.contains("PAYLOAD_POLYMORPHIC_REORDER_INDEPENDENT_STEPS"),
        "payload hardening must support polymorphic calldata padding and bounded independent-step reordering"
    );
}
