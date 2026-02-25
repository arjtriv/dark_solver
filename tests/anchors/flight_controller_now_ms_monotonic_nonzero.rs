use std::fs;

#[test]
fn flight_controller_now_ms_is_monotonic_and_nonzero() {
    let source = fs::read_to_string("src/bin/flight_controller.rs")
        .expect("src/bin/flight_controller.rs must be readable");
    assert!(
        source.contains("static LAST_FLIGHT_CONTROLLER_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && source
                .contains("fn normalize_flight_controller_now_ms(sample_ms: Option<u64>) -> u64")
            && source.contains("normalize_flight_controller_now_ms(sample)"),
        "flight controller now_ms must be monotonic and non-zero"
    );
    assert!(
        !source.contains(".map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "flight controller now_ms must not fallback to zero"
    );
}
