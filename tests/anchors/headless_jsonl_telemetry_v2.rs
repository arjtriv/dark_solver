//! Anchor: headless JSONL telemetry writes (solve cycles) are supported and can be redirected.

use alloy::primitives::Address;

#[test]
fn headless_jsonl_telemetry_writes_solve_cycle_to_overridden_dir() {
    // Disable async so this anchor is deterministic.
    std::env::set_var("HEADLESS_JSONL_TELEMETRY_ASYNC_ENABLED", "false");

    let base =
        std::env::temp_dir().join(format!("dark_solver_headless_jsonl_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("temp dir created");
    std::env::set_var(
        "VERIFICATION_TELEMETRY_DIR",
        base.to_string_lossy().to_string(),
    );

    let target = Address::from([0x33; 20]);
    dark_solver::solver::verification::record_solve_cycle(target, 123u128, "anchor", 3);

    let solve_path = base.join("solve_cycles.jsonl");
    let raw = std::fs::read_to_string(&solve_path).expect("solve_cycles.jsonl must exist");
    assert!(raw.contains("\"phase\":\"anchor\""));
    assert!(raw.contains("\"elapsed_ms\":123"));

    let _ = std::fs::remove_dir_all(&base);
    std::env::remove_var("VERIFICATION_TELEMETRY_DIR");
    std::env::remove_var("HEADLESS_JSONL_TELEMETRY_ASYNC_ENABLED");
}
