use dark_solver::solver::verification::{
    evaluate_memory_profile_window, evaluate_solve_rate_window,
};

fn parse_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn main() {
    let window_secs = parse_u64_env("PRESSURE_REPORT_WINDOW_SECS", 3600);
    let window_ms = window_secs.saturating_mul(1000);

    let memory = match evaluate_memory_profile_window(window_ms) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("[PRESSURE] memory report failed: {err}");
            std::process::exit(2);
        }
    };

    let solve_rate = match evaluate_solve_rate_window(window_ms) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("[PRESSURE] solve-rate report failed: {err}");
            std::process::exit(2);
        }
    };

    println!(
        "[PRESSURE] window_secs={} memory{{pass={} enough_window={} samples={} start_rss_mb={:.2} end_rss_mb={:.2} delta_mb={:.2} max_rss_mb={:.2}}} solve_rate{{pass={} enough_window={} samples={} within_budget={} ratio={:.3}}}",
        window_secs,
        memory.pass,
        memory.enough_window,
        memory.samples,
        memory.start_rss_mb,
        memory.end_rss_mb,
        memory.delta_mb,
        memory.max_rss_mb,
        solve_rate.pass,
        solve_rate.enough_window,
        solve_rate.samples,
        solve_rate.within_budget,
        solve_rate.ratio,
    );

    if memory.pass && solve_rate.pass {
        std::process::exit(0);
    }
    std::process::exit(1);
}
