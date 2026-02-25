use serde::Deserialize;
use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const Z3_TELEMETRY_JSONL: &str = "artifacts/telemetry/z3_stats.jsonl";
const SOLVE_CYCLES_JSONL: &str = "artifacts/telemetry/solve_cycles.jsonl";
const SOLVER_LOG_PATH: &str = "logs/solver.log";
const SOLVE_BUDGET_MS: f64 = 1_800.0;
const MAX_ACTIVE_TARGETS: usize = 8;
const MAX_RECENT_VULNS: usize = 8;
const MAX_RECENT_EXEC_EVENTS: usize = 8;
const MAX_GRAPH_POINTS: usize = 96;
const MAX_LOG_SCAN_LINES: usize = 1_200;
const SCANNER_ACTIVE_WINDOW_MS: u64 = 20_000;
static LAST_FLIGHT_CONTROLLER_NOW_MS: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Deserialize)]
struct Z3TelemetryRecord {
    objective: String,
    #[serde(default = "default_telemetry_target")]
    target: String,
    elapsed_ms: u64,
    sat: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct SolveCycleSample {
    #[serde(default)]
    timestamp_ms: u64,
    target: String,
}

#[derive(Debug, Clone)]
struct DashboardSnapshot {
    scanner_status: String,
    execution_status: String,
    active_targets: Vec<String>,
    recent_vulns: Vec<String>,
    recent_exec_events: Vec<String>,
    z3_load_pct: u16,
    sat_rate_pct: u16,
    sat_count: usize,
    unsat_count: usize,
    pnl_points: Vec<u64>,
}

fn default_telemetry_target() -> String {
    "unknown".to_string()
}

fn read_jsonl_records<T>(path: &str) -> Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(record) = serde_json::from_str::<T>(&line) {
            out.push(record);
        }
    }
    out
}

fn tail_slice<T>(values: &[T], max: usize) -> &[T] {
    if values.len() <= max {
        values
    } else {
        &values[values.len() - max..]
    }
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_flight_controller_now_ms(sample)
}

fn normalize_flight_controller_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_FLIGHT_CONTROLLER_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_FLIGHT_CONTROLLER_NOW_MS.compare_exchange_weak(
            prev,
            normalized,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return normalized,
            Err(actual) => prev = actual,
        }
    }
}

fn scanner_status(cycles: &[SolveCycleSample]) -> String {
    let latest_ts = cycles
        .iter()
        .map(|sample| sample.timestamp_ms)
        .max()
        .unwrap_or(0);
    if latest_ts == 0 {
        return "NO_FEED".to_string();
    }
    let age_ms = now_ms().saturating_sub(latest_ts);
    if age_ms <= SCANNER_ACTIVE_WINDOW_MS {
        "FEEDING".to_string()
    } else {
        "IDLE".to_string()
    }
}

fn short_target(target: &str) -> String {
    let value = target.trim();
    if value.starts_with("0x") && value.len() >= 8 {
        format!("{}...", &value[..8])
    } else if value.is_empty() {
        "unknown".to_string()
    } else {
        value.to_string()
    }
}

fn map_exec_event(line: &str) -> Option<&'static str> {
    if line.contains("[EXEC] Dispatching private bundle via") {
        return Some("SENT");
    }
    if line.contains("Late-solve re-verification failed") {
        return Some("DROP_PREFLIGHT");
    }
    if line.contains("[DRIFT] Pinned-block replay was profitable") {
        return Some("DROP_DRIFT");
    }
    if line.contains("Shadow Simulation completed but was unprofitable") {
        return Some("DROP_UNPROFITABLE");
    }
    if line.contains("Shadow Simulation failed") && line.contains("429") {
        return Some("DROP_RPC_429");
    }
    if line.contains("Shadow Simulation failed") {
        return Some("DROP_SHADOW_FAIL");
    }
    if line.contains("Stale Solve dropped") {
        return Some("DROP_STALE");
    }
    if line.contains("Secure handshake failed") {
        return Some("DROP_HANDSHAKE");
    }
    if line.contains("Bundle rejected due to competition signal") {
        return Some("REJECTED_COMPETITION");
    }
    if line.contains("Constructing Bundle (Multi-Builder)") {
        return Some("ATTEMPTED");
    }
    None
}

fn event_label(code: &str) -> &'static str {
    match code {
        "SENT" => "SENT: private submission dispatched",
        "DROP_PREFLIGHT" => "DROPPED: late-solve pre-flight failed",
        "DROP_DRIFT" => "DROPPED: market drift vs pinned block",
        "DROP_UNPROFITABLE" => "DROPPED: shadow replay unprofitable",
        "DROP_RPC_429" => "DROPPED: shadow replay RPC 429",
        "DROP_SHADOW_FAIL" => "DROPPED: shadow replay failed",
        "DROP_STALE" => "DROPPED: stale solve block",
        "DROP_HANDSHAKE" => "DROPPED: private builder handshake failed",
        "REJECTED_COMPETITION" => "REJECTED: competition signal",
        "ATTEMPTED" => "ATTEMPTED: private submission construction started",
        _ => "UNKNOWN",
    }
}

fn read_recent_log_lines(path: &str, max_lines: usize) -> Vec<String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut ring = VecDeque::with_capacity(max_lines);
    for line in reader.lines().map_while(Result::ok) {
        if ring.len() == max_lines {
            let _ = ring.pop_front();
        }
        ring.push_back(line);
    }
    ring.into_iter().collect()
}

fn build_execution_summary_from_lines(lines: &[String]) -> (String, Vec<String>) {
    if lines.is_empty() {
        return (
            "NO_LOG".to_string(),
            vec!["No logs/solver.log found yet".to_string()],
        );
    }

    let mut recent_exec_events = Vec::new();
    let mut last_label: Option<&'static str> = None;
    let mut latest_status = "NO_EXEC_EVENTS".to_string();

    for line in lines.iter().rev() {
        let Some(code) = map_exec_event(line) else {
            continue;
        };
        if latest_status == "NO_EXEC_EVENTS" {
            latest_status = code.to_string();
        }
        let label = event_label(code);
        if last_label == Some(label) {
            continue;
        }
        recent_exec_events.push(label.to_string());
        last_label = Some(label);
        if recent_exec_events.len() >= MAX_RECENT_EXEC_EVENTS {
            break;
        }
    }

    if recent_exec_events.is_empty() {
        recent_exec_events.push("No execution attempts observed".to_string());
    }

    (latest_status, recent_exec_events)
}

fn latest_pulse_line(lines: &[String]) -> Option<&str> {
    lines.iter()
        .rev()
        .find(|line| line.contains("[PULSE]"))
        .map(String::as_str)
}

fn scanner_status_from_pulse(line: &str) -> Option<String> {
    let marker = "| status:";
    let idx = line.find(marker)?;
    let raw = line[idx + marker.len()..].trim();
    if raw.is_empty() {
        return None;
    }
    let normalized = match raw {
        "ACTIVE" => "FEEDING",
        value => value,
    };
    Some(normalized.to_string())
}

fn queue_summary_from_pulse(line: &str) -> Option<String> {
    let marker = "| q:";
    let idx = line.find(marker)?;
    let rest = &line[idx + 2..];
    let end = rest.find("| status:").unwrap_or(rest.len());
    let summary = rest[..end].trim();
    if summary.is_empty() {
        None
    } else {
        Some(summary.to_string())
    }
}

fn build_snapshot() -> DashboardSnapshot {
    let z3_records = read_jsonl_records::<Z3TelemetryRecord>(Z3_TELEMETRY_JSONL);
    let cycle_records = read_jsonl_records::<SolveCycleSample>(SOLVE_CYCLES_JSONL);
    let log_lines = read_recent_log_lines(SOLVER_LOG_PATH, MAX_LOG_SCAN_LINES);

    let mut seen_targets = BTreeSet::new();
    let mut active_targets = Vec::new();
    for sample in cycle_records.iter().rev() {
        if seen_targets.insert(sample.target.clone()) {
            active_targets.push(sample.target.clone());
            if active_targets.len() >= MAX_ACTIVE_TARGETS {
                break;
            }
        }
    }
    if active_targets.is_empty() {
        active_targets.push("n/a".to_string());
    }

    let z3_tail = tail_slice(&z3_records, MAX_GRAPH_POINTS);
    let mut scanner_status = scanner_status(&cycle_records);
    let (execution_status, recent_exec_events) = build_execution_summary_from_lines(&log_lines);
    if let Some(pulse_line) = latest_pulse_line(&log_lines) {
        if let Some(pulse_status) = scanner_status_from_pulse(pulse_line) {
            scanner_status = pulse_status;
        }
        if let Some(queue_summary) = queue_summary_from_pulse(pulse_line) {
            if active_targets.len() == 1 && active_targets[0] == "n/a" {
                active_targets.clear();
            }
            active_targets.insert(0, format!("runtime {queue_summary}"));
            if active_targets.len() > MAX_ACTIVE_TARGETS {
                active_targets.truncate(MAX_ACTIVE_TARGETS);
            }
        }
    }
    let avg_elapsed = if z3_tail.is_empty() {
        0.0
    } else {
        let sum: f64 = z3_tail.iter().map(|r| r.elapsed_ms as f64).sum();
        sum / z3_tail.len() as f64
    };
    let z3_load_pct = ((avg_elapsed / SOLVE_BUDGET_MS) * 100.0).clamp(0.0, 100.0) as u16;

    let sat_rate_pct = if z3_tail.is_empty() {
        0
    } else {
        let sat_count = z3_tail.iter().filter(|r| r.sat).count();
        ((sat_count as f64 / z3_tail.len() as f64) * 100.0) as u16
    };

    let mut recent_vulns = Vec::new();
    for record in z3_records.iter().rev() {
        // Filter out test/anchor objectives so operator view stays production-relevant.
        if record.objective.contains("anchor") {
            continue;
        }
        if !record.sat {
            continue;
        }
        recent_vulns.push(format!(
            "{} :: {} ({}ms)",
            short_target(&record.target),
            record.objective,
            record.elapsed_ms
        ));
        if recent_vulns.len() >= MAX_RECENT_VULNS {
            break;
        }
    }
    if recent_vulns.is_empty() {
        recent_vulns.push("No SAT findings yet".to_string());
    }

    let mut running = 0i64;
    let mut raw_points = Vec::new();
    for record in z3_tail {
        if record.sat {
            running += 1;
        } else {
            running -= 1;
        }
        raw_points.push(running);
    }
    if raw_points.is_empty() {
        raw_points.push(0);
    }

    let min_point = raw_points.iter().copied().min().unwrap_or(0);
    let offset = if min_point < 0 { -min_point } else { 0 };
    let pnl_points = raw_points
        .into_iter()
        .map(|value| (value + offset) as u64)
        .collect::<Vec<_>>();

    DashboardSnapshot {
        scanner_status,
        execution_status,
        active_targets,
        recent_vulns,
        recent_exec_events,
        z3_load_pct,
        sat_rate_pct,
        sat_count: z3_tail.iter().filter(|r| r.sat).count(),
        unsat_count: z3_tail.iter().filter(|r| !r.sat).count(),
        pnl_points,
    }
}

fn render_trend(points: &[u64]) -> String {
    if points.len() < 2 {
        return ".".to_string();
    }
    let mut out = String::with_capacity(points.len() - 1);
    for pair in points.windows(2) {
        let ch = if pair[1] > pair[0] {
            '+'
        } else if pair[1] < pair[0] {
            '-'
        } else {
            '='
        };
        out.push(ch);
    }
    out
}

fn render_stdout(snapshot: &DashboardSnapshot) -> io::Result<()> {
    let mut stdout = io::stdout();
    write!(stdout, "\x1B[2J\x1B[H")?;
    writeln!(stdout, "Flight Controller Dashboard (Ctrl+C to quit)")?;
    writeln!(
        stdout,
        "Status: Scanner: {} | Z3 Load %: {} | SAT Rate: {}% | SAT: {} | UNSAT: {}",
        snapshot.scanner_status,
        snapshot.z3_load_pct,
        snapshot.sat_rate_pct,
        snapshot.sat_count,
        snapshot.unsat_count
    )?;
    writeln!(stdout, "Execution: {}", snapshot.execution_status)?;
    writeln!(stdout, "{}", "-".repeat(78))?;
    writeln!(stdout, "Active Targets:")?;
    for target in &snapshot.active_targets {
        writeln!(stdout, "  - {target}")?;
    }
    writeln!(stdout, "{}", "-".repeat(78))?;
    writeln!(stdout, "Recent Vulnerabilities:")?;
    for finding in &snapshot.recent_vulns {
        writeln!(stdout, "  - {finding}")?;
    }
    writeln!(stdout, "{}", "-".repeat(78))?;
    writeln!(stdout, "Recent Execution Outcomes:")?;
    for event in &snapshot.recent_exec_events {
        writeln!(stdout, "  - {event}")?;
    }
    writeln!(stdout, "{}", "-".repeat(78))?;
    writeln!(
        stdout,
        "Profit/Loss Graph (SAT Signal, not USD): {}",
        render_trend(&snapshot.pnl_points)
    )?;
    stdout.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    loop {
        let snapshot = build_snapshot();
        render_stdout(&snapshot)?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nFlight Controller exiting.");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(900)) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_normalize_flight_controller_now_ms_never_returns_zero() {
        super::LAST_FLIGHT_CONTROLLER_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_flight_controller_now_ms(None), 1);
        assert!(super::normalize_flight_controller_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_flight_controller_now_ms_clamps_clock_regressions() {
        super::LAST_FLIGHT_CONTROLLER_NOW_MS.store(100, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_flight_controller_now_ms(Some(90)), 100);
        assert_eq!(super::normalize_flight_controller_now_ms(Some(150)), 150);
    }
}
