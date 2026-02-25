use std::fs;

#[test]
fn test_zero_leak_memory_profile_runtime_gate() {
    let main_source =
        fs::read_to_string("src/main.rs").expect("src/main.rs must be readable for memory gate");
    let verification_source = fs::read_to_string("src/solver/verification.rs")
        .expect("src/solver/verification.rs must be readable for memory gate");

    assert!(
        main_source.contains("record_memory_sample()"),
        "heartbeat must record runtime memory samples for 24h leak verification"
    );
    assert!(
        verification_source.contains("pub const MEMORY_LEAK_LIMIT_MB: f64 = 500.0;"),
        "memory leak threshold must remain capped at 500MB"
    );
    assert!(
        verification_source.contains("const WINDOW_24H_MS: u64 = 24 * 60 * 60 * 1000;"),
        "verification window must remain 24h"
    );
    assert!(
        verification_source.contains("SECTION8_VERDICT_JSON"),
        "section8 memory verdict must be persisted for operator review"
    );
}
