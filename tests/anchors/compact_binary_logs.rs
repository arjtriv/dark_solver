//! Anchor: telemetry supports compact framed-bincode binary logs alongside JSONL.

use alloy::primitives::Address;
use dark_solver::solver::telemetry::{objective_scope, record_solver_stats};
use std::fs;
use z3::{Config, Context, Solver};

#[test]
fn compact_binary_logs_write_bin_files_when_enabled() {
    std::env::set_var("COMPACT_BINARY_LOGS_ENABLED", "true");
    std::env::set_var("HEADLESS_JSONL_TELEMETRY_ASYNC_ENABLED", "false");
    std::env::set_var("TELEMETRY_ASYNC_BUFFER_ENABLED", "false");

    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let _scope = objective_scope(
        "compact_binary_logs_anchor",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    record_solver_stats(&solver, 3, true);

    let z3_bin = fs::metadata("artifacts/telemetry/z3_stats.bin")
        .expect("z3_stats.bin must exist when COMPACT_BINARY_LOGS_ENABLED");
    assert!(z3_bin.len() > 0);

    let base = std::env::temp_dir().join(format!("dark_solver_compact_bin_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("temp dir created");
    std::env::set_var(
        "VERIFICATION_TELEMETRY_DIR",
        base.to_string_lossy().to_string(),
    );
    let target = Address::from([0x33; 20]);
    dark_solver::solver::verification::record_solve_cycle(target, 12u128, "anchor", 3);

    let solve_bin = fs::metadata(base.join("solve_cycles.bin"))
        .expect("solve_cycles.bin must exist when COMPACT_BINARY_LOGS_ENABLED");
    assert!(solve_bin.len() > 0);

    let _ = fs::remove_dir_all(&base);
    std::env::remove_var("VERIFICATION_TELEMETRY_DIR");
    std::env::remove_var("TELEMETRY_ASYNC_BUFFER_ENABLED");
    std::env::remove_var("HEADLESS_JSONL_TELEMETRY_ASYNC_ENABLED");
    std::env::remove_var("COMPACT_BINARY_LOGS_ENABLED");
}
