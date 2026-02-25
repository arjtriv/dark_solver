use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, OnceLock,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use z3::{Solver, StatisticsValue};

const TELEMETRY_DIR: &str = "artifacts/telemetry";
const TELEMETRY_JSONL: &str = "artifacts/telemetry/z3_stats.jsonl";
const TELEMETRY_BIN: &str = "artifacts/telemetry/z3_stats.bin";
const TELEMETRY_DASHBOARD: &str = "artifacts/telemetry/z3_dashboard.html";
const BINARY_KEY_STATS_LIMIT: usize = 64;
const DASHBOARD_HISTORY_LIMIT: usize = 200;
const COMPACT_KEEP: usize = 4_000;
#[cfg(test)]
const COMPACT_TRIGGER: usize = 4_500;
const DASHBOARD_WRITE_MIN_INTERVAL_MS: u64 = 1_000;
const COMPACT_MIN_INTERVAL_MS: u64 = 15_000;
const COMPACT_SIZE_TRIGGER_BYTES: u64 = 6_000_000;
const PERF_BUDGET_MS: u64 = 1_800;
const CONFLICT_BLOWUP_THRESHOLD: f64 = 100_000.0;
const MEMORY_BLOWUP_MB: f64 = 2_048.0;
const ASYNC_BUFFER_CAPACITY: usize = 2_048;
const ASYNC_BUFFER_MAX_DRAIN: usize = 128;
static LAST_SOLVER_TELEMETRY_NOW_MS: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static ACTIVE_OBJECTIVE: RefCell<Option<String>> = const { RefCell::new(None) };
    static ACTIVE_TARGET: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub struct ObjectiveScopeGuard;

pub fn objective_scope(name: &str, target: &str) -> ObjectiveScopeGuard {
    ACTIVE_OBJECTIVE.with(|slot| {
        *slot.borrow_mut() = Some(name.to_string());
    });
    ACTIVE_TARGET.with(|slot| {
        *slot.borrow_mut() = Some(target.to_string());
    });
    ObjectiveScopeGuard
}

impl Drop for ObjectiveScopeGuard {
    fn drop(&mut self) {
        ACTIVE_OBJECTIVE.with(|slot| {
            *slot.borrow_mut() = None;
        });
        ACTIVE_TARGET.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Z3TelemetryRecord {
    timestamp_ms: u64,
    objective: String,
    #[serde(default = "default_record_target")]
    target: String,
    elapsed_ms: u64,
    sat: bool,
    blowup_signal: bool,
    conflicts: Option<f64>,
    restarts: Option<f64>,
    memory_mb: Option<f64>,
    max_memory_mb: Option<f64>,
    key_stats: BTreeMap<String, f64>,
}

impl crate::utils::binary_log::BinaryEncode for Z3TelemetryRecord {
    fn encode_binary(&self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        crate::utils::binary_log::write_u64_le(&mut out, self.timestamp_ms);
        crate::utils::binary_log::write_string(&mut out, &self.objective)?;
        crate::utils::binary_log::write_string(&mut out, &self.target)?;
        crate::utils::binary_log::write_u64_le(&mut out, self.elapsed_ms);
        crate::utils::binary_log::write_bool(&mut out, self.sat);
        crate::utils::binary_log::write_bool(&mut out, self.blowup_signal);
        crate::utils::binary_log::write_opt_f64_le(&mut out, self.conflicts);
        crate::utils::binary_log::write_opt_f64_le(&mut out, self.restarts);
        crate::utils::binary_log::write_opt_f64_le(&mut out, self.memory_mb);
        crate::utils::binary_log::write_opt_f64_le(&mut out, self.max_memory_mb);

        let count = self.key_stats.len().min(BINARY_KEY_STATS_LIMIT);
        crate::utils::binary_log::write_u32_le(&mut out, count as u32);
        for (key, value) in self.key_stats.iter().take(count) {
            crate::utils::binary_log::write_string(&mut out, key)?;
            crate::utils::binary_log::write_f64_le(&mut out, *value);
        }

        Ok(out)
    }
}

struct TelemetryState {
    hydrated: bool,
    records: VecDeque<Z3TelemetryRecord>,
    last_dashboard_write_ms: u64,
    last_compact_ms: u64,
}

fn telemetry_state() -> &'static Mutex<TelemetryState> {
    static STATE: OnceLock<Mutex<TelemetryState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(TelemetryState {
            hydrated: false,
            records: VecDeque::new(),
            last_dashboard_write_ms: 0,
            last_compact_ms: 0,
        })
    })
}

fn telemetry_async_enabled() -> bool {
    match std::env::var("TELEMETRY_ASYNC_BUFFER_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn async_sender() -> Option<&'static mpsc::Sender<Z3TelemetryRecord>> {
    static SENDER: OnceLock<mpsc::Sender<Z3TelemetryRecord>> = OnceLock::new();
    static DROPPED: AtomicU64 = AtomicU64::new(0);

    if !telemetry_async_enabled() {
        return None;
    }

    if let Some(sender) = SENDER.get() {
        return Some(sender);
    }

    // Only initialize when a Tokio runtime is available. Otherwise, remain sync.
    let handle = tokio::runtime::Handle::try_current().ok()?;
    let (tx, mut rx) = mpsc::channel::<Z3TelemetryRecord>(ASYNC_BUFFER_CAPACITY);
    let _ = SENDER.set(tx);
    let sender = SENDER.get()?;

    handle.spawn(async move {
        while let Some(first) = rx.recv().await {
            let mut batch = Vec::with_capacity(ASYNC_BUFFER_MAX_DRAIN.min(8));
            batch.push(first);
            while batch.len() < ASYNC_BUFFER_MAX_DRAIN {
                match rx.try_recv() {
                    Ok(next) => batch.push(next),
                    Err(_) => break,
                }
            }

            // Do all disk I/O off the main solver path.
            let write_res = tokio::task::spawn_blocking(move || {
                for record in batch {
                    if let Err(err) = persist_record_fast(&record) {
                        eprintln!("[WARN] Telemetry write failed: {err}");
                    }
                }
            })
            .await;

            if write_res.is_err() {
                // Avoid noisy logs: count drops and emit a sparse warning.
                let dropped = DROPPED.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                if dropped.is_power_of_two() {
                    eprintln!(
                        "[WARN] Telemetry async worker write task failed; dropped_batches={dropped}"
                    );
                }
            }
        }
    });

    Some(sender)
}

pub fn record_solver_stats(solver: &Solver<'_>, elapsed_ms: u64, sat: bool) {
    let stats = solver.get_statistics();
    let key_stats = stats
        .entries()
        .map(|entry| {
            let value = match entry.value {
                StatisticsValue::UInt(v) => v as f64,
                StatisticsValue::Double(v) => v,
            };
            (entry.key, value)
        })
        .collect::<BTreeMap<_, _>>();

    let conflicts = pick_metric(&key_stats, &["conflicts"], &["conflict"]);
    let restarts = pick_metric(&key_stats, &["restarts"], &["restart"]);
    let memory_mb = pick_metric(&key_stats, &["memory"], &["memory"]);
    let max_memory_mb = pick_metric(&key_stats, &["max memory"], &["max memory"]);
    let peak_memory = max_memory_mb.or(memory_mb);

    let blowup_signal = elapsed_ms > PERF_BUDGET_MS
        || conflicts.unwrap_or(0.0) >= CONFLICT_BLOWUP_THRESHOLD
        || peak_memory.unwrap_or(0.0) >= MEMORY_BLOWUP_MB;

    let record = Z3TelemetryRecord {
        timestamp_ms: now_ms(),
        objective: active_objective(),
        target: active_target(),
        elapsed_ms,
        sat,
        blowup_signal,
        conflicts,
        restarts,
        memory_mb,
        max_memory_mb,
        key_stats,
    };

    if let Some(sender) = async_sender() {
        if sender.try_send(record).is_ok() {
            return;
        }
        // If the buffer is saturated, fail open: keep solving and skip telemetry.
        static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);
        let dropped = DROPPED_RECORDS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if dropped.is_power_of_two() {
            eprintln!("[WARN] Telemetry async buffer saturated; dropped_records={dropped}.");
        }
        return;
    }

    if let Err(err) = persist_record_fast(&record) {
        eprintln!("[WARN] Telemetry write failed: {err}");
    }
}

fn active_objective() -> String {
    ACTIVE_OBJECTIVE
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn active_target() -> String {
    ACTIVE_TARGET
        .with(|slot| slot.borrow().clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn default_record_target() -> String {
    "unknown".to_string()
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_solver_telemetry_now_ms(sample)
}

fn normalize_solver_telemetry_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_SOLVER_TELEMETRY_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_SOLVER_TELEMETRY_NOW_MS.compare_exchange_weak(
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

fn pick_metric(
    stats: &BTreeMap<String, f64>,
    exact_keys: &[&str],
    contains_keys: &[&str],
) -> Option<f64> {
    for &key in exact_keys {
        if let Some(value) = stats.get(key) {
            return Some(*value);
        }
    }

    let lowercase_stats = stats
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), *v))
        .collect::<BTreeMap<_, _>>();

    for &key in contains_keys {
        let key_lower = key.to_ascii_lowercase();
        if let Some((_, value)) = lowercase_stats.iter().find(|(k, _)| k.contains(&key_lower)) {
            return Some(*value);
        }
    }

    None
}

fn tail_hydrate_records(jsonl_path: &Path) -> VecDeque<Z3TelemetryRecord> {
    let mut records = VecDeque::new();
    let Ok(file) = File::open(jsonl_path) else {
        return records;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(record) = serde_json::from_str::<Z3TelemetryRecord>(&line) {
            records.push_back(record);
            while records.len() > COMPACT_KEEP {
                records.pop_front();
            }
        }
    }
    records
}

fn persist_record_fast(record: &Z3TelemetryRecord) -> std::io::Result<()> {
    let telemetry_dir = Path::new(TELEMETRY_DIR);
    let jsonl_path = Path::new(TELEMETRY_JSONL);
    let bin_path = Path::new(TELEMETRY_BIN);
    let dashboard_path = Path::new(TELEMETRY_DASHBOARD);

    fs::create_dir_all(telemetry_dir)?;
    let jsonl_existed = jsonl_path.exists();
    if jsonl_existed {
        let mut guard = match telemetry_state().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if !guard.hydrated {
            // Avoid expensive hydration when telemetry is already large.
            let small_enough = jsonl_path
                .metadata()
                .ok()
                .map(|m| m.len() <= COMPACT_SIZE_TRIGGER_BYTES)
                .unwrap_or(true);
            if small_enough {
                guard.records = tail_hydrate_records(jsonl_path);
            }
            guard.hydrated = true;
        }
    }

    append_jsonl(jsonl_path, record)?;
    if crate::utils::binary_log::compact_binary_logs_enabled() {
        crate::utils::binary_log::append_framed_encoded(bin_path, record)?;
    }

    let now = record.timestamp_ms;
    let mut dashboard_needed = false;
    let mut compact_needed = false;
    let mut snapshot = Vec::new();

    {
        let mut guard = match telemetry_state().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if !guard.hydrated {
            guard.hydrated = true;
        }

        guard.records.push_back(record.clone());
        while guard.records.len() > COMPACT_KEEP {
            guard.records.pop_front();
        }

        let dashboard_missing = !dashboard_path.exists();
        if dashboard_missing
            || now.saturating_sub(guard.last_dashboard_write_ms) >= DASHBOARD_WRITE_MIN_INTERVAL_MS
        {
            guard.last_dashboard_write_ms = now;
            dashboard_needed = true;
        }

        let size_triggered = jsonl_path
            .metadata()
            .ok()
            .map(|m| m.len() >= COMPACT_SIZE_TRIGGER_BYTES)
            .unwrap_or(false);
        if size_triggered && now.saturating_sub(guard.last_compact_ms) >= COMPACT_MIN_INTERVAL_MS {
            guard.last_compact_ms = now;
            compact_needed = true;
        }

        if dashboard_needed || compact_needed {
            snapshot.extend(guard.records.iter().cloned());
        }
    }

    if compact_needed {
        rewrite_jsonl(jsonl_path, &snapshot)?;
    }
    if dashboard_needed {
        let dashboard_html = render_dashboard(&snapshot);
        fs::write(dashboard_path, dashboard_html)?;
    }

    Ok(())
}

#[cfg(test)]
fn persist_record_to(
    record: &Z3TelemetryRecord,
    telemetry_dir: &Path,
    jsonl_path: &Path,
    dashboard_path: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(telemetry_dir)?;
    append_jsonl(jsonl_path, record)?;
    // Used by tests and offline tooling: keep this deterministic even if it's not "hot path".
    let mut records = read_records(jsonl_path)?;
    if records.len() > COMPACT_TRIGGER {
        let start = records.len().saturating_sub(COMPACT_KEEP);
        records = records.split_off(start);
        rewrite_jsonl(jsonl_path, &records)?;
    }

    let dashboard_html = render_dashboard(&records);
    fs::write(dashboard_path, dashboard_html)?;
    Ok(())
}

fn append_jsonl(path: &Path, record: &Z3TelemetryRecord) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(record)
        .map_err(|e| std::io::Error::other(format!("serialize telemetry: {e}")))?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn rewrite_jsonl(path: &Path, records: &[Z3TelemetryRecord]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    for record in records {
        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::other(format!("serialize telemetry: {e}")))?;
        writeln!(file, "{line}")?;
    }
    Ok(())
}

#[cfg(test)]
fn read_records(path: &Path) -> std::io::Result<Vec<Z3TelemetryRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(record) = serde_json::from_str::<Z3TelemetryRecord>(&line) {
            records.push(record);
        }
    }

    Ok(records)
}

fn render_dashboard(records: &[Z3TelemetryRecord]) -> String {
    let mut html = String::new();
    let run_count = records.len();
    let blowup_count = records.iter().filter(|r| r.blowup_signal).count();
    let latest = records.last();
    let latest_objective = latest
        .map(|r| html_escape(&r.objective))
        .unwrap_or_else(|| "n/a".to_string());
    let latest_elapsed = latest
        .map(|r| r.elapsed_ms.to_string())
        .unwrap_or_else(|| "n/a".to_string());

    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<title>Z3 Telemetry Dashboard</title>");
    html.push_str("<style>");
    html.push_str(
        "body{font-family:Menlo,Monaco,monospace;background:#0d1117;color:#d1d5db;padding:20px;}",
    );
    html.push_str(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:16px;}");
    html.push_str(
        ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;}",
    );
    html.push_str("table{border-collapse:collapse;width:100%;font-size:12px;}");
    html.push_str("th,td{border:1px solid #30363d;padding:6px;text-align:left;}");
    html.push_str("th{background:#1f2937;}");
    html.push_str(".blowup{color:#fca5a5;font-weight:700;}");
    html.push_str("</style></head><body>");
    html.push_str("<h1>Z3 Solver Telemetry</h1>");

    let _ = write!(
        html,
        "<div class=\"cards\">\
            <div class=\"card\"><strong>Total Runs</strong><div>{run_count}</div></div>\
            <div class=\"card\"><strong>Blowup Signals</strong><div>{blowup_count}</div></div>\
            <div class=\"card\"><strong>Latest Objective</strong><div>{latest_objective}</div></div>\
            <div class=\"card\"><strong>Latest Elapsed (ms)</strong><div>{latest_elapsed}</div></div>\
         </div>"
    );

    html.push_str("<table><thead><tr>");
    html.push_str("<th>Timestamp</th><th>Target</th><th>Objective</th><th>Elapsed(ms)</th><th>SAT</th><th>Conflicts</th><th>Restarts</th><th>Memory(MB)</th><th>Max Memory(MB)</th><th>Signal</th>");
    html.push_str("</tr></thead><tbody>");

    for record in records.iter().rev().take(DASHBOARD_HISTORY_LIMIT) {
        let signal_class = if record.blowup_signal { "blowup" } else { "" };
        let _ = write!(
            html,
            "<tr>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td class=\"{}\">{}</td>\
            </tr>",
            record.timestamp_ms,
            html_escape(&record.target),
            html_escape(&record.objective),
            record.elapsed_ms,
            record.sat,
            record
                .conflicts
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "n/a".to_string()),
            record
                .restarts
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "n/a".to_string()),
            record
                .memory_mb
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "n/a".to_string()),
            record
                .max_memory_mb
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "n/a".to_string()),
            signal_class,
            if record.blowup_signal { "BLOWUP" } else { "ok" }
        );
    }

    html.push_str("</tbody></table></body></html>");
    html
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::{persist_record_to, pick_metric, render_dashboard, Z3TelemetryRecord};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::{env, fs};

    #[test]
    fn test_pick_metric_prefers_exact_key() {
        let mut stats = BTreeMap::new();
        stats.insert("conflicts".to_string(), 42.0);
        stats.insert("arith conflicts".to_string(), 999.0);

        let value = pick_metric(&stats, &["conflicts"], &["conflict"]);
        assert_eq!(value, Some(42.0));
    }

    #[test]
    fn test_render_dashboard_contains_blowup_row() {
        let records = vec![Z3TelemetryRecord {
            timestamp_ms: 123,
            objective: "OracleSpotObjective".to_string(),
            target: "0x1111111111111111111111111111111111111111".to_string(),
            elapsed_ms: 2_100,
            sat: true,
            blowup_signal: true,
            conflicts: Some(123_456.0),
            restarts: Some(17.0),
            memory_mb: Some(500.5),
            max_memory_mb: Some(1_200.0),
            key_stats: BTreeMap::new(),
        }];

        let html = render_dashboard(&records);
        assert!(html.contains("OracleSpotObjective"));
        assert!(html.contains("BLOWUP"));
    }

    #[test]
    fn test_persist_record_writes_jsonl_and_dashboard() {
        let base = temp_test_dir("z3-telemetry");
        let jsonl = base.join("z3_stats.jsonl");
        let dashboard = base.join("z3_dashboard.html");

        let record = Z3TelemetryRecord {
            timestamp_ms: 999,
            objective: "GenericProfitObjective".to_string(),
            target: "0x2222222222222222222222222222222222222222".to_string(),
            elapsed_ms: 100,
            sat: false,
            blowup_signal: false,
            conflicts: Some(10.0),
            restarts: Some(2.0),
            memory_mb: Some(30.0),
            max_memory_mb: Some(40.0),
            key_stats: BTreeMap::new(),
        };

        let write_res = persist_record_to(&record, &base, &jsonl, &dashboard);
        assert!(write_res.is_ok());
        assert!(jsonl.exists());
        assert!(dashboard.exists());

        let dashboard_html = fs::read_to_string(&dashboard).unwrap_or_default();
        assert!(dashboard_html.contains("GenericProfitObjective"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn test_normalize_solver_telemetry_now_ms_never_returns_zero() {
        super::LAST_SOLVER_TELEMETRY_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_solver_telemetry_now_ms(None), 1);
        assert!(super::normalize_solver_telemetry_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_solver_telemetry_now_ms_clamps_clock_regressions() {
        super::LAST_SOLVER_TELEMETRY_NOW_MS.store(1000, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_solver_telemetry_now_ms(Some(900)), 1000);
        assert_eq!(super::normalize_solver_telemetry_now_ms(Some(1300)), 1300);
    }

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let mut dir = env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        dir.push(format!("{prefix}-{nanos}"));
        dir
    }
}
