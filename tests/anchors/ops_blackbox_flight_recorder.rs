use std::fs;

#[test]
fn test_ops_blackbox_flight_recorder_is_wired() {
    let blackbox_source = fs::read_to_string("src/utils/blackbox.rs")
        .expect("src/utils/blackbox.rs must be readable for blackbox audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for blackbox wiring audit");

    assert!(
        blackbox_source.contains("VecDeque")
            && blackbox_source.contains("BLACKBOX_BUFFER_SIZE")
            && blackbox_source.contains("crash_report_")
            && blackbox_source.contains("install_panic_hook_once")
            && blackbox_source.contains("dump(\"panic\")"),
        "blackbox utility must maintain a bounded ring buffer and dump crash reports on panic"
    );
    assert!(
        main_source.contains("install_panic_hook_once")
            && main_source.contains("blackbox::record")
            && main_source.contains("dump(\"sigterm\")")
            && main_source.contains("dump(\"ctrl_c\")"),
        "runtime must install panic hook, record key events, and dump blackbox on termination paths"
    );
}
