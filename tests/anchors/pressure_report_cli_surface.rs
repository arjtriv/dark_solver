use std::fs;

#[test]
fn pressure_report_cli_surface_stays_scriptable() {
    let source = fs::read_to_string("src/bin/pressure_report.rs").expect("read pressure_report.rs");
    assert!(
        source.contains("--window-secs"),
        "pressure_report should keep an explicit window flag"
    );
    assert!(
        source.contains("--telemetry-dir"),
        "pressure_report should keep telemetry dir overrides"
    );
    assert!(source.contains("--json"), "pressure_report should keep json output");
}
