use std::fs;

#[test]
fn flight_controller_renders_scanner_status_signal() {
    let source = fs::read_to_string("src/bin/flight_controller.rs")
        .expect("src/bin/flight_controller.rs must be readable for scanner-status audit");

    for needle in [
        "SCANNER_ACTIVE_WINDOW_MS",
        "fn scanner_status",
        "\"FEEDING\"",
        "\"IDLE\"",
        "\"NO_FEED\"",
        "Status: Scanner:",
    ] {
        assert!(
            source.contains(needle),
            "flight controller must include `{needle}` to disambiguate 0-load state"
        );
    }
}
