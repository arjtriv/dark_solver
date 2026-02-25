use std::fs;

#[test]
fn test_startup_clock_drift_guard_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for clock guard audit");

    assert!(
        main_source.contains("STARTUP_CLOCK_DRIFT_SERVERS")
            && main_source.contains("time.google.com:123")
            && main_source.contains("pool.ntp.org:123")
            && main_source.contains("ntp_clock_offset_ms")
            && main_source.contains("enforce_startup_clock_drift_guard")
            && main_source.contains("STARTUP_CLOCK_DRIFT_MAX_OFFSET_MS"),
        "runtime must define and enforce an NTP-backed startup clock drift guard with explicit max offset"
    );
    assert!(
        main_source.contains("enforce_startup_clock_drift_guard().await")
            && main_source.contains("startup_clock_drift_guard")
            && main_source.contains("emit_critical"),
        "main startup must execute the drift guard and emit a critical telemetry signal on failure"
    );
}
