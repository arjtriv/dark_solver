use std::fs;

#[test]
fn public_binaries_keep_using_shared_cli_helpers() {
    let cli = fs::read_to_string("src/utils/cli.rs").expect("read cli.rs");
    let deep = fs::read_to_string("src/bin/deep_sniper.rs").expect("read deep_sniper.rs");
    let replay = fs::read_to_string("src/bin/shadow_replay.rs").expect("read shadow_replay.rs");
    let pressure = fs::read_to_string("src/bin/pressure_report.rs").expect("read pressure_report.rs");
    let bench = fs::read_to_string("src/bin/benchmark_rpc.rs").expect("read benchmark_rpc.rs");

    assert!(cli.contains("env_first_nonempty"), "shared cli helpers should exist");
    assert!(deep.contains("dark_solver::utils::cli"), "deep_sniper should use shared helpers");
    assert!(replay.contains("dark_solver::utils::cli"), "shadow_replay should use shared helpers");
    assert!(pressure.contains("dark_solver::utils::cli"), "pressure_report should use shared helpers");
    assert!(bench.contains("dark_solver::utils::cli"), "benchmark_rpc should use shared helpers");
}
