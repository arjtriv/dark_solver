//! Anchor Test: telemetry writes dashboard artifacts and keeps objective labels.

use dark_solver::solver::telemetry::{objective_scope, record_solver_stats};
use std::fs;
use z3::{Config, Context, Solver};

#[test]
fn test_telemetry_writes_artifacts() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let _scope = objective_scope(
        "ledger_sync_telemetry_anchor",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    record_solver_stats(&solver, 25, true);

    let jsonl = fs::read_to_string("artifacts/telemetry/z3_stats.jsonl")
        .expect("telemetry JSONL must exist");
    assert!(jsonl.contains("ledger_sync_telemetry_anchor"));

    let dashboard = fs::read_to_string("artifacts/telemetry/z3_dashboard.html")
        .expect("telemetry dashboard must exist");
    assert!(dashboard.contains("Z3 Solver Telemetry"));
}
