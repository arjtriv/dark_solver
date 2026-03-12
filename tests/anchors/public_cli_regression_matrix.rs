use std::fs;

#[test]
fn public_cli_regression_checks_cover_the_main_binaries() {
    let deep = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    let replay = fs::read_to_string("src/bin/shadow_replay.rs").expect("read shadow_replay.rs");
    let pressure = fs::read_to_string("src/bin/pressure_report.rs").expect("read pressure_report.rs");
    let bench = fs::read_to_string("src/bin/benchmark_rpc.rs").expect("read benchmark_rpc.rs");

    assert!(deep.contains("expect_err"), "deep_sniper should keep negative parser coverage");
    assert!(replay.contains("expect_err"), "shadow_replay should keep negative parser coverage");
    assert!(pressure.contains("expect_err"), "pressure_report should keep negative parser coverage");
    assert!(bench.contains("expect_err"), "benchmark_rpc should keep negative parser coverage");
}
