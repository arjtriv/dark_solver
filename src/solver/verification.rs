use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const TELEMETRY_DIR: &str = "artifacts/telemetry";
const MEMORY_JSONL: &str = "artifacts/telemetry/runtime_memory.jsonl";
const SOLVE_CYCLES_JSONL: &str = "artifacts/telemetry/solve_cycles.jsonl";
const SECTION8_VERDICT_JSON: &str = "artifacts/telemetry/section8_verdict.json";
const MEMORY_BIN_NAME: &str = "runtime_memory.bin";
const SOLVE_CYCLES_BIN_NAME: &str = "solve_cycles.bin";
const MEMORY_JSONL_NAME: &str = "runtime_memory.jsonl";
const SOLVE_CYCLES_JSONL_NAME: &str = "solve_cycles.jsonl";
const SECTION8_VERDICT_JSON_NAME: &str = "section8_verdict.json";
const COMPACT_KEEP: usize = 12_000;
const COMPACT_TRIGGER: usize = 13_000;
const WINDOW_24H_MS: u64 = 24 * 60 * 60 * 1000;
pub const MEMORY_LEAK_LIMIT_MB: f64 = 500.0;
pub const SOLVE_BUDGET_MS: u64 = 1_800;
pub const SOLVE_RATE_TARGET: f64 = 0.95;
const VERDICT_REFRESH_MIN_INTERVAL_MS: u64 = 60_000;
const ASYNC_BUFFER_CAPACITY: usize = 4_096;
const ASYNC_BUFFER_MAX_DRAIN: usize = 256;
static LAST_VERIFICATION_NOW_MS: AtomicU64 = AtomicU64::new(1);

fn telemetry_dir() -> PathBuf {
    std::env::var("VERIFICATION_TELEMETRY_DIR")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(TELEMETRY_DIR))
}

fn memory_jsonl_path() -> PathBuf {
    if std::env::var("VERIFICATION_TELEMETRY_DIR")
        .ok()
        .is_some_and(|raw| !raw.trim().is_empty())
    {
        telemetry_dir().join(MEMORY_JSONL_NAME)
    } else {
        PathBuf::from(MEMORY_JSONL)
    }
}

fn solve_cycles_jsonl_path() -> PathBuf {
    if std::env::var("VERIFICATION_TELEMETRY_DIR")
        .ok()
        .is_some_and(|raw| !raw.trim().is_empty())
    {
        telemetry_dir().join(SOLVE_CYCLES_JSONL_NAME)
    } else {
        PathBuf::from(SOLVE_CYCLES_JSONL)
    }
}

fn memory_bin_path() -> PathBuf {
    if std::env::var("VERIFICATION_TELEMETRY_DIR")
        .ok()
        .is_some_and(|raw| !raw.trim().is_empty())
    {
        telemetry_dir().join(MEMORY_BIN_NAME)
    } else {
        PathBuf::from(TELEMETRY_DIR).join(MEMORY_BIN_NAME)
    }
}

fn solve_cycles_bin_path() -> PathBuf {
    if std::env::var("VERIFICATION_TELEMETRY_DIR")
        .ok()
        .is_some_and(|raw| !raw.trim().is_empty())
    {
        telemetry_dir().join(SOLVE_CYCLES_BIN_NAME)
    } else {
        PathBuf::from(TELEMETRY_DIR).join(SOLVE_CYCLES_BIN_NAME)
    }
}

fn verdict_json_path() -> PathBuf {
    if std::env::var("VERIFICATION_TELEMETRY_DIR")
        .ok()
        .is_some_and(|raw| !raw.trim().is_empty())
    {
        telemetry_dir().join(SECTION8_VERDICT_JSON_NAME)
    } else {
        PathBuf::from(SECTION8_VERDICT_JSON)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemorySample {
    timestamp_ms: u64,
    pid: u32,
    rss_mb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SolveCycleSample {
    timestamp_ms: u64,
    target: String,
    phase: String,
    elapsed_ms: u64,
    within_budget: bool,
    reentrancy_depth: usize,
}

impl crate::utils::binary_log::BinaryEncode for MemorySample {
    fn encode_binary(&self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(32);
        crate::utils::binary_log::write_u64_le(&mut out, self.timestamp_ms);
        crate::utils::binary_log::write_u32_le(&mut out, self.pid);
        crate::utils::binary_log::write_f64_le(&mut out, self.rss_mb);
        Ok(out)
    }
}

impl crate::utils::binary_log::BinaryEncode for SolveCycleSample {
    fn encode_binary(&self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        crate::utils::binary_log::write_u64_le(&mut out, self.timestamp_ms);
        crate::utils::binary_log::write_string(&mut out, &self.target)?;
        crate::utils::binary_log::write_string(&mut out, &self.phase)?;
        crate::utils::binary_log::write_u64_le(&mut out, self.elapsed_ms);
        crate::utils::binary_log::write_bool(&mut out, self.within_budget);
        let depth: u32 = self.reentrancy_depth.try_into().unwrap_or(u32::MAX);
        crate::utils::binary_log::write_u32_le(&mut out, depth);
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLeakReport {
    pub enough_window: bool,
    pub samples: usize,
    pub start_rss_mb: f64,
    pub end_rss_mb: f64,
    pub delta_mb: f64,
    pub max_rss_mb: f64,
    pub min_rss_mb: f64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolveRateReport {
    pub enough_window: bool,
    pub samples: usize,
    pub within_budget: usize,
    pub ratio: f64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Section8Verdict {
    timestamp_ms: u64,
    memory: MemoryLeakReport,
    solve_rate: SolveRateReport,
}

struct VerdictThrottleState {
    last_refresh_ms: u64,
}

fn verdict_throttle() -> &'static Mutex<VerdictThrottleState> {
    static STATE: OnceLock<Mutex<VerdictThrottleState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(VerdictThrottleState { last_refresh_ms: 0 }))
}

fn headless_async_enabled() -> bool {
    match std::env::var("HEADLESS_JSONL_TELEMETRY_ASYNC_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

#[derive(Debug, Clone)]
enum TelemetryMsg {
    Memory(MemorySample),
    SolveCycle(SolveCycleSample),
}

fn async_sender() -> Option<&'static mpsc::Sender<TelemetryMsg>> {
    static SENDER: OnceLock<mpsc::Sender<TelemetryMsg>> = OnceLock::new();
    static DROPPED_BATCHES: AtomicU64 = AtomicU64::new(0);

    if !headless_async_enabled() {
        return None;
    }

    if let Some(sender) = SENDER.get() {
        return Some(sender);
    }

    let handle = tokio::runtime::Handle::try_current().ok()?;
    let (tx, mut rx) = mpsc::channel::<TelemetryMsg>(ASYNC_BUFFER_CAPACITY);
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

            let write_res = tokio::task::spawn_blocking(move || {
                let dir = telemetry_dir();
                let memory_path = dir.join(MEMORY_JSONL_NAME);
                let solve_path = dir.join(SOLVE_CYCLES_JSONL_NAME);
                let memory_bin = dir.join(MEMORY_BIN_NAME);
                let solve_bin = dir.join(SOLVE_CYCLES_BIN_NAME);
                let mut newest_ts = 0u64;
                for msg in batch {
                    match msg {
                        TelemetryMsg::Memory(sample) => {
                            newest_ts = newest_ts.max(sample.timestamp_ms);
                            if let Err(err) = persist_record(
                                memory_path.as_path(),
                                Some(memory_bin.as_path()),
                                &sample,
                            ) {
                                eprintln!("[WARN] Runtime memory profile write failed: {err}");
                            }
                        }
                        TelemetryMsg::SolveCycle(sample) => {
                            newest_ts = newest_ts.max(sample.timestamp_ms);
                            if let Err(err) = persist_record(
                                solve_path.as_path(),
                                Some(solve_bin.as_path()),
                                &sample,
                            ) {
                                eprintln!("[WARN] Solve-cycle profile write failed: {err}");
                            }
                        }
                    }
                }

                if newest_ts > 0 {
                    maybe_refresh_section8_verdict(newest_ts);
                }
            })
            .await;

            if write_res.is_err() {
                let dropped = DROPPED_BATCHES
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if dropped.is_power_of_two() {
                    eprintln!(
                        "[WARN] Headless telemetry worker task failed; dropped_batches={dropped}"
                    );
                }
            }
        }
    });

    Some(sender)
}

fn maybe_refresh_section8_verdict(now_ms: u64) {
    let verdict_path = verdict_json_path();
    let mut guard = match verdict_throttle().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let missing = !verdict_path.exists();
    if missing || now_ms.saturating_sub(guard.last_refresh_ms) >= VERDICT_REFRESH_MIN_INTERVAL_MS {
        guard.last_refresh_ms = now_ms;
        drop(guard);
        refresh_section8_verdict();
    }
}

pub fn record_memory_sample() {
    let sample = match current_rss_mb() {
        Some(rss_mb) => MemorySample {
            timestamp_ms: now_ms(),
            pid: std::process::id(),
            rss_mb,
        },
        None => return,
    };

    if let Some(sender) = async_sender() {
        if sender.try_send(TelemetryMsg::Memory(sample)).is_ok() {
            return;
        }
        static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);
        let dropped = DROPPED_RECORDS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if dropped.is_power_of_two() {
            eprintln!("[WARN] Headless telemetry buffer saturated; dropped_records={dropped}.");
        }
        return;
    }

    let path = memory_jsonl_path();
    let bin_path = memory_bin_path();
    if let Err(err) = persist_record(path.as_path(), Some(bin_path.as_path()), &sample) {
        eprintln!("[WARN] Runtime memory profile write failed: {err}");
        return;
    }

    maybe_refresh_section8_verdict(sample.timestamp_ms);
}

pub fn record_solve_cycle(target: Address, elapsed_ms: u128, phase: &str, reentrancy_depth: usize) {
    let elapsed = elapsed_ms.min(u128::from(u64::MAX)) as u64;
    let sample = SolveCycleSample {
        timestamp_ms: now_ms(),
        target: format!("{target:#x}"),
        phase: phase.to_string(),
        elapsed_ms: elapsed,
        within_budget: elapsed <= SOLVE_BUDGET_MS,
        reentrancy_depth,
    };

    if let Some(sender) = async_sender() {
        if sender.try_send(TelemetryMsg::SolveCycle(sample)).is_ok() {
            return;
        }
        static DROPPED_RECORDS: AtomicU64 = AtomicU64::new(0);
        let dropped = DROPPED_RECORDS
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if dropped.is_power_of_two() {
            eprintln!("[WARN] Headless telemetry buffer saturated; dropped_records={dropped}.");
        }
        return;
    }

    let path = solve_cycles_jsonl_path();
    let bin_path = solve_cycles_bin_path();
    if let Err(err) = persist_record(path.as_path(), Some(bin_path.as_path()), &sample) {
        eprintln!("[WARN] Solve-cycle profile write failed: {err}");
        return;
    }

    maybe_refresh_section8_verdict(sample.timestamp_ms);
}

fn refresh_section8_verdict() {
    let memory_report = match evaluate_memory_profile_24h() {
        Ok(report) => report,
        Err(err) => {
            eprintln!("[WARN] Memory profile evaluation failed: {err}");
            return;
        }
    };

    let solve_report = match evaluate_solve_rate_24h() {
        Ok(report) => report,
        Err(err) => {
            eprintln!("[WARN] Solve-rate evaluation failed: {err}");
            return;
        }
    };

    let verdict = Section8Verdict {
        timestamp_ms: now_ms(),
        memory: memory_report,
        solve_rate: solve_report,
    };

    let verdict_path = verdict_json_path();
    if let Some(parent) = verdict_path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!("[WARN] Failed creating telemetry directory: {err}");
            return;
        }
    }

    if let Err(err) = fs::write(
        verdict_path.as_path(),
        serde_json::to_string_pretty(&verdict)
            .unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_string()),
    ) {
        eprintln!("[WARN] Section8 verdict write failed: {err}");
    }
}

pub fn evaluate_memory_profile_24h() -> std::io::Result<MemoryLeakReport> {
    let path = memory_jsonl_path();
    let records = read_records::<MemorySample>(path.as_path())?;
    Ok(build_memory_report(&records))
}

pub fn evaluate_solve_rate_24h() -> std::io::Result<SolveRateReport> {
    let path = solve_cycles_jsonl_path();
    let records = read_records::<SolveCycleSample>(path.as_path())?;
    Ok(build_solve_rate_report(&records))
}

pub fn evaluate_memory_profile_window(window_ms: u64) -> std::io::Result<MemoryLeakReport> {
    let path = memory_jsonl_path();
    let records = read_records::<MemorySample>(path.as_path())?;
    Ok(build_memory_report_window(&records, window_ms))
}

pub fn evaluate_solve_rate_window(window_ms: u64) -> std::io::Result<SolveRateReport> {
    let path = solve_cycles_jsonl_path();
    let records = read_records::<SolveCycleSample>(path.as_path())?;
    Ok(build_solve_rate_report_window(&records, window_ms))
}

fn build_memory_report(records: &[MemorySample]) -> MemoryLeakReport {
    build_memory_report_window(records, WINDOW_24H_MS)
}

fn build_memory_report_window(records: &[MemorySample], window_ms: u64) -> MemoryLeakReport {
    let windowed = within_window(
        window_ms,
        records.iter().map(|sample| sample.timestamp_ms),
        records,
    );
    if windowed.is_empty() {
        return MemoryLeakReport {
            enough_window: false,
            samples: 0,
            start_rss_mb: 0.0,
            end_rss_mb: 0.0,
            delta_mb: 0.0,
            max_rss_mb: 0.0,
            min_rss_mb: 0.0,
            pass: false,
        };
    }

    let first_ts = windowed.first().map(|s| s.timestamp_ms).unwrap_or(0);
    let last_ts = windowed.last().map(|s| s.timestamp_ms).unwrap_or(0);
    let enough_window = last_ts.saturating_sub(first_ts) >= window_ms;

    let start_rss_mb = windowed.first().map(|s| s.rss_mb).unwrap_or(0.0);
    let end_rss_mb = windowed.last().map(|s| s.rss_mb).unwrap_or(0.0);
    let min_rss_mb = windowed
        .iter()
        .map(|s| s.rss_mb)
        .fold(f64::INFINITY, f64::min);
    let max_rss_mb = windowed
        .iter()
        .map(|s| s.rss_mb)
        .fold(f64::NEG_INFINITY, f64::max);
    let delta_mb = end_rss_mb - start_rss_mb;

    MemoryLeakReport {
        enough_window,
        samples: windowed.len(),
        start_rss_mb,
        end_rss_mb,
        delta_mb,
        max_rss_mb,
        min_rss_mb,
        pass: enough_window && delta_mb <= MEMORY_LEAK_LIMIT_MB,
    }
}

fn build_solve_rate_report(records: &[SolveCycleSample]) -> SolveRateReport {
    build_solve_rate_report_window(records, WINDOW_24H_MS)
}

fn build_solve_rate_report_window(records: &[SolveCycleSample], window_ms: u64) -> SolveRateReport {
    let windowed = within_window(
        window_ms,
        records.iter().map(|sample| sample.timestamp_ms),
        records,
    );
    let depth_filtered: Vec<&SolveCycleSample> = windowed
        .into_iter()
        .filter(|sample| sample.reentrancy_depth >= 3)
        .collect();
    if depth_filtered.is_empty() {
        return SolveRateReport {
            enough_window: false,
            samples: 0,
            within_budget: 0,
            ratio: 0.0,
            pass: false,
        };
    }

    let first_ts = depth_filtered.first().map(|s| s.timestamp_ms).unwrap_or(0);
    let last_ts = depth_filtered.last().map(|s| s.timestamp_ms).unwrap_or(0);
    let enough_window = last_ts.saturating_sub(first_ts) >= window_ms;

    let within_budget = depth_filtered
        .iter()
        .filter(|sample| sample.within_budget)
        .count();
    let samples = depth_filtered.len();
    let ratio = within_budget as f64 / samples as f64;

    SolveRateReport {
        enough_window,
        samples,
        within_budget,
        ratio,
        pass: enough_window && ratio >= SOLVE_RATE_TARGET,
    }
}

fn persist_record<T: Serialize + crate::utils::binary_log::BinaryEncode>(
    path: &Path,
    bin_path: Option<&Path>,
    record: &T,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    append_jsonl(path, record)?;
    if crate::utils::binary_log::compact_binary_logs_enabled() {
        if let Some(bin_path) = bin_path {
            crate::utils::binary_log::append_framed_encoded(bin_path, record)?;
        }
    }

    let mut lines = read_lines(path)?;
    if lines.len() > COMPACT_TRIGGER {
        let start = lines.len().saturating_sub(COMPACT_KEEP);
        lines = lines.split_off(start);
        rewrite_lines(path, &lines)?;
    }

    Ok(())
}

fn append_jsonl<T: Serialize>(path: &Path, record: &T) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(record)
        .map_err(|e| std::io::Error::other(format!("serialize runtime sample: {e}")))?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn read_records<T>(path: &Path) -> std::io::Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut parsed = Vec::new();
    for line in read_lines(path)? {
        if let Ok(record) = serde_json::from_str::<T>(&line) {
            parsed.push(record);
        }
    }
    Ok(parsed)
}

fn read_lines(path: &Path) -> std::io::Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().map_while(Result::ok).collect())
}

fn rewrite_lines(path: &Path, lines: &[String]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn within_window<T>(window_ms: u64, timestamps: impl Iterator<Item = u64>, records: &[T]) -> Vec<&T>
where
    T: HasTimestamp,
{
    let latest = timestamps.max().unwrap_or(0);
    let start = latest.saturating_sub(window_ms);
    records
        .iter()
        .filter(|record| record.timestamp_ms() >= start)
        .collect()
}

trait HasTimestamp {
    fn timestamp_ms(&self) -> u64;
}

impl HasTimestamp for MemorySample {
    fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
}

impl HasTimestamp for SolveCycleSample {
    fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64);
    normalize_verification_now_ms(sample)
}

fn normalize_verification_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_VERIFICATION_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_VERIFICATION_NOW_MS.compare_exchange_weak(
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

#[cfg(unix)]
fn current_rss_mb() -> Option<f64> {
    let pid = std::process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let kb = stdout.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(kb / 1024.0)
}

#[cfg(not(unix))]
fn current_rss_mb() -> Option<f64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(hours: u64) -> u64 {
        hours * 60 * 60 * 1000
    }

    #[test]
    fn test_memory_report_requires_full_24h_window() {
        let records = vec![
            MemorySample {
                timestamp_ms: ms(0),
                pid: 1,
                rss_mb: 100.0,
            },
            MemorySample {
                timestamp_ms: ms(23),
                pid: 1,
                rss_mb: 120.0,
            },
        ];
        let report = build_memory_report(&records);
        assert!(!report.enough_window);
        assert!(!report.pass);
    }

    #[test]
    fn test_memory_report_flags_growth_over_limit() {
        let records = vec![
            MemorySample {
                timestamp_ms: ms(0),
                pid: 1,
                rss_mb: 100.0,
            },
            MemorySample {
                timestamp_ms: ms(24),
                pid: 1,
                rss_mb: 700.5,
            },
        ];
        let report = build_memory_report(&records);
        assert!(report.enough_window);
        assert!(!report.pass);
        assert!(report.delta_mb > MEMORY_LEAK_LIMIT_MB);
    }

    #[test]
    fn test_solve_rate_report_enforces_95_percent_budget() {
        let mut records = Vec::new();
        for idx in 0..100usize {
            records.push(SolveCycleSample {
                timestamp_ms: (idx as u64 * WINDOW_24H_MS) / 99,
                target: "0x0".to_string(),
                phase: "primary".to_string(),
                elapsed_ms: if idx < 95 { 1_700 } else { 2_100 },
                within_budget: idx < 95,
                reentrancy_depth: 3,
            });
        }
        let report = build_solve_rate_report(&records);
        assert!(report.enough_window);
        assert_eq!(report.within_budget, 95);
        assert!(report.pass);
    }

    #[test]
    fn test_normalize_verification_now_ms_never_returns_zero() {
        super::LAST_VERIFICATION_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_verification_now_ms(None), 1);
        assert!(super::normalize_verification_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_verification_now_ms_clamps_clock_regressions() {
        super::LAST_VERIFICATION_NOW_MS.store(444, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_verification_now_ms(Some(400)), 444);
        assert_eq!(super::normalize_verification_now_ms(Some(555)), 555);
    }
}
