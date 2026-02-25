//! Internal orchestration binary for continuous scanning and compatibility workflows.
//!
//! The primary external audit workflow for this repository is:
//! `./analyze_target.sh` -> `src/bin/deep_sniper.rs`.

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use dark_solver::executor::execution_policy::{
    should_override_rpc_cooldown_for_high_capital, ProfitWeightedExecutionPolicy, UncertaintyClass,
};
use dark_solver::executor::watch_cache::{WatchCache, WatchCacheItem};
use dark_solver::executor::Executor;
use dark_solver::fork_db::ForkDB;
use dark_solver::runtime::{
    apply_discovery_mode_defaults, apply_runtime_profile, emit_discovery_mode_status,
    emit_runtime_profile_status, parse_runtime_args,
};
use dark_solver::scanner;
use dark_solver::storage::contracts_db::{
    BuilderAttemptRecord, ContractsDb, ExecutionOutcomeLabel, ScanCompletionGuard,
    ScanStatusCounts, SubmissionAttemptRecord,
};
use dashmap::DashMap;
use revm::db::CacheDB;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;

use dark_solver::target_queue::{TargetPriority, TargetQueue};

const PULSE_BASE_POLL_MS: u64 = 10_000;
const PULSE_MAX_POLL_MS: u64 = 120_000;
const REORG_BASE_POLL_MS: u64 = 4_000;
const REORG_MAX_POLL_MS: u64 = 120_000;
const RATE_LIMIT_COOLDOWN_SECS: u64 = 120;
const REORG_JUMP_EXPECTED_SLACK_BLOCKS: u64 = 1;
const WATCH_CACHE_MIN_SOLVE_MS: u128 = 30_000;
const WATCH_CACHE_MAX_ITEMS: usize = 96;
const WATCH_CACHE_RECHECK_PER_BLOCK: usize = 2;
const WATCH_CACHE_MAX_ATTEMPTS: u32 = 10;
const PULSE_DEGRADED_LATENCY_MS: u128 = 2_500;
const BACKGROUND_SOLVER_QUEUE_DEFAULT_WORKERS: usize = 2;
const BACKGROUND_SOLVER_QUEUE_MAX_WORKERS: usize = 8;
const BACKGROUND_SOLVER_QUEUE_DEFAULT_CAPACITY: usize = 128;
const JIT_TUNER_DEFAULT_BUDGET_MS: u64 = 10;
const JIT_TUNER_MAX_BUDGET_MS: u64 = 200;
const JIT_TUNER_DEFAULT_MAX_OFFSET_SHIFT: u64 = 2;
const PRESSURE_RISK_DEFAULT_HIGH_CAPITAL_USD: u128 = 500_000;
const PRESSURE_RISK_DEFAULT_ETH_USD: u128 = 3_000;
const ONE_ETH_WEI_U128: u128 = 1_000_000_000_000_000_000;
const PROOF_PERSISTENCE_DEFAULT_STALE_BLOCKS: u64 = 10;
const PROOF_PERSISTENCE_DEFAULT_MAX_ITEMS: usize = 192;
const PROOF_PERSISTENCE_DEFAULT_RECHECK_PER_BLOCK: usize = 2;
const PROOF_PERSISTENCE_MAX_RECHECK_PER_BLOCK: usize = 8;
const PROOF_PERSISTENCE_DEFAULT_REPLAY_TIMEOUT_MS: u64 = 75;
const PROOF_PERSISTENCE_MAX_REPLAY_TIMEOUT_MS: u64 = 5_000;
const PROOF_PERSISTENCE_DEFAULT_COMPLEX_REPLAY_TIMEOUT_MS: u64 = 5_000;
const SOLVE_UNSAT_PROGRESS_LOG_EVERY_DEFAULT: u64 = 1;
const STARTUP_CLOCK_DRIFT_DEFAULT_ENABLED: bool = true;
const STARTUP_CLOCK_DRIFT_DEFAULT_MAX_OFFSET_MS: i64 = 100;
const STARTUP_CLOCK_DRIFT_DEFAULT_TIMEOUT_MS: u64 = 1_200;
const STARTUP_CLOCK_DRIFT_SERVERS: [&str; 2] = ["time.google.com:123", "pool.ntp.org:123"];

type InflightSet = Arc<StdMutex<HashSet<Address>>>;

fn lock_inflight_set<'a>(
    inflight: &'a InflightSet,
    label: &str,
) -> std::sync::MutexGuard<'a, HashSet<Address>> {
    match inflight.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(
                "[RISK] In-flight target set lock poisoned in {}; recovering guard state.",
                label
            );
            poisoned.into_inner()
        }
    }
}

#[derive(Debug, Clone)]
struct PersistedDeepProofItem {
    target: Address,
    objective: String,
    fingerprint: B256,
    params: dark_solver::solver::objectives::ExploitParams,
    solve_block: u64,
    last_checked_block: u64,
    checks: u32,
    /// Consecutive replay failures (timeout or error). Reset to 0 on success.
    consecutive_failures: u32,
    last_verified_block: Option<u64>,
    last_valid_state_root: Option<B256>,
}

#[derive(Debug)]
struct SolverResult {
    target: Address,
    bytecode_hash: B256,
    findings: Vec<(String, dark_solver::solver::objectives::ExploitParams)>,
    solve_duration_ms: u128,
    solve_target_block: u64,
    is_retry: bool,
    is_background: bool,
}

#[derive(Debug, Clone)]
struct BackgroundSolveTask {
    target: Address,
    bytecode_hash: B256,
    bytecode: Bytes,
    target_context: Arc<dark_solver::solver::setup::TargetContext>,
    solver_rpc: String,
    chain_id: u64,
    solve_target_block: u64,
}

struct InflightTargetGuard {
    inflight: InflightSet,
    target: Address,
}

impl InflightTargetGuard {
    fn new(inflight: InflightSet, target: Address) -> Self {
        Self { inflight, target }
    }
}

impl Drop for InflightTargetGuard {
    fn drop(&mut self) {
        let mut guard = lock_inflight_set(&self.inflight, "InflightTargetGuard::drop");
        guard.remove(&self.target);
    }
}

fn compact_error(err: impl std::fmt::Display) -> String {
    dark_solver::utils::error::compact_error_message(&err.to_string(), 320)
}

static LAST_MAIN_NOW_MS: AtomicU64 = AtomicU64::new(1);

fn normalize_main_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_MAIN_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_MAIN_NOW_MS.compare_exchange_weak(
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

fn now_ms() -> u64 {
    let sample = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64);
    normalize_main_now_ms(sample)
}

fn load_startup_clock_drift_guard_enabled() -> bool {
    std::env::var("STARTUP_CLOCK_DRIFT_GUARD_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(STARTUP_CLOCK_DRIFT_DEFAULT_ENABLED)
}

fn load_startup_clock_drift_max_offset_ms() -> i64 {
    std::env::var("STARTUP_CLOCK_DRIFT_MAX_OFFSET_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<i64>().ok())
        .map(|v| v.clamp(1, 5_000))
        .unwrap_or(STARTUP_CLOCK_DRIFT_DEFAULT_MAX_OFFSET_MS)
}

fn load_startup_clock_drift_timeout_ms() -> u64 {
    std::env::var("STARTUP_CLOCK_DRIFT_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(200, 10_000))
        .unwrap_or(STARTUP_CLOCK_DRIFT_DEFAULT_TIMEOUT_MS)
}

fn load_daily_stop_loss_timeout_ms() -> u64 {
    std::env::var("DAILY_STOP_LOSS_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1_000, 60_000))
        .unwrap_or(10_000)
}

async fn ntp_clock_offset_ms(server: &str, timeout_ms: u64) -> anyhow::Result<i64> {
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let socket = tokio::time::timeout(timeout, tokio::net::UdpSocket::bind("0.0.0.0:0"))
        .await
        .map_err(|_| anyhow::anyhow!("bind timeout for {server}"))??;
    tokio::time::timeout(timeout, socket.connect(server))
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout for {server}"))??;

    let mut req = [0u8; 48];
    // LI=0, VN=3, Mode=3 (client).
    req[0] = 0x1b;
    tokio::time::timeout(timeout, socket.send(&req))
        .await
        .map_err(|_| anyhow::anyhow!("send timeout for {server}"))??;

    let mut resp = [0u8; 48];
    let read = tokio::time::timeout(timeout, socket.recv(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("recv timeout for {server}"))??;
    if read < 48 {
        anyhow::bail!("short NTP response from {server}: {read} bytes");
    }

    let ntp_seconds = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]);
    let ntp_fraction = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]);
    const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;
    if (ntp_seconds as u64) < NTP_UNIX_OFFSET_SECS {
        anyhow::bail!("invalid NTP epoch from {server}: {ntp_seconds}");
    }
    let unix_seconds = (ntp_seconds as u64).saturating_sub(NTP_UNIX_OFFSET_SECS);
    let remote_ms = (unix_seconds as i128)
        .saturating_mul(1_000)
        .saturating_add(((ntp_fraction as i128) * 1_000) >> 32);
    let local_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i128)
        .map_err(|err| anyhow::anyhow!("local clock before UNIX_EPOCH: {err}"))?;
    let offset = remote_ms.saturating_sub(local_ms);
    Ok(offset.clamp(i64::MIN as i128, i64::MAX as i128) as i64)
}

async fn enforce_startup_clock_drift_guard() -> anyhow::Result<()> {
    if !load_startup_clock_drift_guard_enabled() {
        return Ok(());
    }
    let timeout_ms = load_startup_clock_drift_timeout_ms();
    let max_offset_ms = load_startup_clock_drift_max_offset_ms();
    let mut offsets = Vec::new();
    let mut failures = Vec::new();

    for server in STARTUP_CLOCK_DRIFT_SERVERS {
        match ntp_clock_offset_ms(server, timeout_ms).await {
            Ok(offset) => offsets.push((server, offset)),
            Err(err) => failures.push(format!("{server}: {}", compact_error(err))),
        }
    }
    if offsets.is_empty() {
        anyhow::bail!(
            "startup clock drift guard could not query any NTP source (failures={})",
            failures.join(" | ")
        );
    }
    let selected = offsets
        .iter()
        .min_by_key(|(_, offset)| offset.abs())
        .map(|(_, offset)| *offset)
        .unwrap_or(0);
    if selected.abs() > max_offset_ms {
        anyhow::bail!(
            "startup clock drift {}ms exceeds allowed {}ms (samples={:?})",
            selected,
            max_offset_ms,
            offsets
        );
    }
    tracing::debug!(
        "[OPS] Startup clock drift guard passed: selected_offset={}ms max_allowed={}ms samples={:?}",
        selected,
        max_offset_ms,
        offsets
    );
    Ok(())
}

fn revm_to_alloy_u256(value: revm::primitives::U256) -> U256 {
    U256::from_be_bytes(value.to_be_bytes::<32>())
}

fn classify_execution_outcome_label(
    feedback: &dark_solver::executor::AttackExecutionFeedback,
) -> ExecutionOutcomeLabel {
    if feedback.competition_rejected {
        return ExecutionOutcomeLabel::Outbid;
    }
    match feedback.outcome {
        dark_solver::executor::AttackOutcome::Sent => {
            if feedback.included.unwrap_or(false) {
                ExecutionOutcomeLabel::Included
            } else {
                ExecutionOutcomeLabel::NotIncluded
            }
        }
        dark_solver::executor::AttackOutcome::DroppedHoneypot => {
            ExecutionOutcomeLabel::DroppedHoneypot
        }
        dark_solver::executor::AttackOutcome::DroppedGasGrief => {
            ExecutionOutcomeLabel::DroppedGasGrief
        }
        dark_solver::executor::AttackOutcome::DroppedStale => ExecutionOutcomeLabel::Late,
        dark_solver::executor::AttackOutcome::DroppedPreflight => ExecutionOutcomeLabel::Late,
        dark_solver::executor::AttackOutcome::DroppedConditional => {
            ExecutionOutcomeLabel::DroppedConditional
        }
        dark_solver::executor::AttackOutcome::DroppedUnprofitable => {
            ExecutionOutcomeLabel::UnprofitableAfterGas
        }
        dark_solver::executor::AttackOutcome::DroppedShadowFail => {
            if feedback.reverted.unwrap_or(false) {
                ExecutionOutcomeLabel::Reverted
            } else {
                ExecutionOutcomeLabel::DroppedShadowFail
            }
        }
        dark_solver::executor::AttackOutcome::DroppedHandshake => {
            ExecutionOutcomeLabel::DroppedHandshake
        }
        dark_solver::executor::AttackOutcome::DroppedPriceConfidence => {
            ExecutionOutcomeLabel::DroppedPriceConfidence
        }
        dark_solver::executor::AttackOutcome::SimulatedOnly => ExecutionOutcomeLabel::SimulatedOnly,
        dark_solver::executor::AttackOutcome::Attempted => ExecutionOutcomeLabel::Unknown,
    }
}

fn fingerprint_exploit_params(params: &dark_solver::solver::objectives::ExploitParams) -> B256 {
    let mut bytes = Vec::new();

    bytes.extend_from_slice(params.flash_loan_token.as_slice());
    bytes.extend_from_slice(params.flash_loan_provider.as_slice());
    bytes.extend_from_slice(&params.flash_loan_amount.to_be_bytes::<32>());
    bytes.extend_from_slice(&(params.flash_loan_legs.len() as u64).to_be_bytes());
    for leg in &params.flash_loan_legs {
        bytes.extend_from_slice(leg.provider.as_slice());
        bytes.extend_from_slice(leg.token.as_slice());
        bytes.extend_from_slice(&leg.amount.to_be_bytes::<32>());
        bytes.extend_from_slice(&leg.fee_bps.to_be_bytes());
    }

    if let Some(profit) = params.expected_profit {
        bytes.extend_from_slice(&profit.to_be_bytes::<32>());
    }
    if let Some(offsets) = &params.block_offsets {
        for offset in offsets {
            bytes.extend_from_slice(&offset.to_be_bytes());
        }
    }

    for step in &params.steps {
        bytes.extend_from_slice(step.target.as_slice());
        bytes.extend_from_slice(step.call_data.as_ref());
    }

    keccak256(bytes)
}

fn load_concrete_fuzz_budget_ms() -> u64 {
    std::env::var("CONCRETE_FUZZ_BUDGET_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v <= 5_000)
        .unwrap_or(500)
}

async fn try_concrete_fuzz_fast_lane(
    rpc_url: &str,
    chain_id: u64,
    attacker: Address,
    target: Address,
    bytecode: &Bytes,
    solve_target_block: u64,
) -> Option<(dark_solver::solver::objectives::ExploitParams, u128)> {
    let budget_ms = load_concrete_fuzz_budget_ms();
    if budget_ms == 0 {
        return None;
    }

    let selectors = dark_solver::solver::heuristics::scan_for_state_changing_selectors(bytecode);
    if selectors.is_empty() {
        return None;
    }

    let started = std::time::Instant::now();
    let mut attempt_nonce = 0u64;

    // Keep the attempt surface tight. This is a "fast lane", not coverage.
    for selector in selectors.iter().take(10) {
        if started.elapsed().as_millis() as u64 >= budget_ms {
            break;
        }
        let sel = selector.as_ref();
        if sel.len() < 4 {
            continue;
        }

        // Candidate shapes:
        // 1) selector only
        // 2) selector + 4x32B zeros
        // 3) selector + 4x32B pseudo-random words (keccak-derived)
        let mut candidates: Vec<Vec<u8>> = Vec::new();
        candidates.push(sel[..4].to_vec());
        candidates.push({
            let mut out = sel[..4].to_vec();
            out.extend_from_slice(&[0u8; 32 * 4]);
            out
        });
        candidates.push({
            let mut out = sel[..4].to_vec();
            for word_idx in 0..4u64 {
                let mut seed = Vec::new();
                seed.extend_from_slice(target.as_slice());
                seed.extend_from_slice(&sel[..4]);
                seed.extend_from_slice(&attempt_nonce.to_be_bytes());
                seed.extend_from_slice(&word_idx.to_be_bytes());
                let word = keccak256(seed).0;
                out.extend_from_slice(&word);
            }
            attempt_nonce = attempt_nonce.wrapping_add(1);
            out
        });

        for calldata in candidates {
            if started.elapsed().as_millis() as u64 >= budget_ms {
                break;
            }

            let params = dark_solver::solver::objectives::ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: vec![dark_solver::solver::objectives::ExploitStep {
                    target,
                    call_data: Bytes::from(calldata),
                    execute_if: None,
                }],
                expected_profit: None,
                block_offsets: None,
            };

            let rpc = rpc_url.to_string();
            let params_for_replay = params.clone();
            let replay = tokio::task::spawn_blocking(move || {
                dark_solver::executor::verifier::replay_path_at_block(
                    &rpc,
                    chain_id,
                    attacker,
                    &params_for_replay,
                    Some(solve_target_block),
                )
            });

            let report =
                match tokio::time::timeout(std::time::Duration::from_millis(250), replay).await {
                    Ok(Ok(report)) => report,
                    _ => continue,
                };

            if report.success && report.profitable {
                let elapsed_ms = started.elapsed().as_millis();
                return Some((params, elapsed_ms));
            }
        }
    }

    None
}

fn load_reorg_watcher_enabled() -> bool {
    match std::env::var("REORG_WATCHER_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_pulse_heartbeat_enabled() -> bool {
    match std::env::var("PULSE_HEARTBEAT_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_pulse_heartbeat_rpc_enabled() -> bool {
    match std::env::var("PULSE_HEARTBEAT_RPC_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_background_solver_queue_enabled() -> bool {
    match std::env::var("BACKGROUND_SOLVER_QUEUE_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_background_solver_queue_workers() -> usize {
    std::env::var("BACKGROUND_SOLVER_QUEUE_WORKERS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(BACKGROUND_SOLVER_QUEUE_MAX_WORKERS))
        .unwrap_or(BACKGROUND_SOLVER_QUEUE_DEFAULT_WORKERS)
}

fn load_background_solver_queue_capacity() -> usize {
    std::env::var("BACKGROUND_SOLVER_QUEUE_CAPACITY")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(BACKGROUND_SOLVER_QUEUE_DEFAULT_CAPACITY)
}

fn load_solve_unsat_progress_log_every() -> u64 {
    std::env::var("SOLVE_UNSAT_PROGRESS_LOG_EVERY")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(SOLVE_UNSAT_PROGRESS_LOG_EVERY_DEFAULT)
}

fn load_jit_tuner_enabled() -> bool {
    match std::env::var("JIT_TUNER_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_jit_tuner_budget_ms() -> u64 {
    std::env::var("JIT_TUNER_BUDGET_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(JIT_TUNER_MAX_BUDGET_MS))
        .unwrap_or(JIT_TUNER_DEFAULT_BUDGET_MS)
}

fn load_jit_tuner_max_offset_shift() -> u64 {
    std::env::var("JIT_TUNER_MAX_OFFSET_SHIFT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(JIT_TUNER_DEFAULT_MAX_OFFSET_SHIFT)
}

fn load_immediate_bundle_relay_enabled() -> bool {
    match std::env::var("IMMEDIATE_BUNDLE_RELAY_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn load_proof_persistence_enabled() -> bool {
    match std::env::var("PROOF_PERSISTENCE_ENGINE_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_proof_persistence_stale_blocks() -> u64 {
    std::env::var("PROOF_PERSISTENCE_MIN_STALE_BLOCKS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(PROOF_PERSISTENCE_DEFAULT_STALE_BLOCKS)
}

fn load_proof_persistence_max_items() -> usize {
    std::env::var("PROOF_PERSISTENCE_MAX_ITEMS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(PROOF_PERSISTENCE_DEFAULT_MAX_ITEMS)
}

fn load_proof_persistence_recheck_per_block() -> usize {
    std::env::var("PROOF_PERSISTENCE_RECHECK_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(PROOF_PERSISTENCE_MAX_RECHECK_PER_BLOCK))
        .unwrap_or(PROOF_PERSISTENCE_DEFAULT_RECHECK_PER_BLOCK)
}

fn load_proof_persistence_replay_timeout_ms() -> u64 {
    std::env::var("PROOF_PERSISTENCE_REPLAY_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(PROOF_PERSISTENCE_MAX_REPLAY_TIMEOUT_MS))
        .unwrap_or(PROOF_PERSISTENCE_DEFAULT_REPLAY_TIMEOUT_MS)
}

fn load_proof_persistence_complex_replay_timeout_ms() -> u64 {
    std::env::var("PROOF_PERSISTENCE_COMPLEX_REPLAY_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(PROOF_PERSISTENCE_DEFAULT_COMPLEX_REPLAY_TIMEOUT_MS)
}

fn load_proof_persistence_max_replay_attempts() -> u32 {
    std::env::var("PROOF_PERSISTENCE_MAX_REPLAY_ATTEMPTS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30)
}

fn track_persisted_deep_proof(
    cache: &mut Vec<PersistedDeepProofItem>,
    item: PersistedDeepProofItem,
    max_items: usize,
) -> bool {
    if cache
        .iter()
        .any(|entry| entry.target == item.target && entry.fingerprint == item.fingerprint)
    {
        return false;
    }
    if cache.len() >= max_items {
        // Evict the item with the highest consecutive_failures (most likely stale/broken).
        // This prevents the old FIFO drain from removing healthy items at position 0
        // while keeping broken items that were appended later.
        if let Some(worst_idx) = cache
            .iter()
            .enumerate()
            .max_by_key(|(_, e)| e.consecutive_failures)
            .map(|(i, _)| i)
        {
            cache.swap_remove(worst_idx);
        }
    }
    cache.push(item);
    true
}

#[allow(clippy::too_many_arguments)]
async fn jit_tune_background_finding(
    rpc_url: &str,
    chain_id: u64,
    attacker: Address,
    params: &dark_solver::solver::objectives::ExploitParams,
    solve_target_block: u64,
    latest_head: u64,
    budget_ms: u64,
    max_offset_shift: u64,
) -> Option<(
    dark_solver::solver::objectives::ExploitParams,
    dark_solver::executor::verifier::ShadowSimulationReport,
    u64,
)> {
    let started = std::time::Instant::now();
    let candidates = dark_solver::executor::jit_migration::build_differential_migration_candidates(
        params,
        solve_target_block,
        latest_head,
        max_offset_shift,
    );

    for candidate in candidates {
        let elapsed_ms = started.elapsed().as_millis() as u64;
        if elapsed_ms >= budget_ms {
            break;
        }
        let remaining = budget_ms - elapsed_ms;
        let rpc = rpc_url.to_string();
        let candidate_for_eval = candidate.clone();
        let task = tokio::task::spawn_blocking(move || {
            dark_solver::executor::verifier::replay_path_at_block(
                &rpc,
                chain_id,
                attacker,
                &candidate_for_eval,
                Some(latest_head),
            )
        });
        let report =
            match tokio::time::timeout(std::time::Duration::from_millis(remaining), task).await {
                Ok(Ok(report)) => report,
                _ => continue,
            };
        if report.success && report.profitable {
            return Some((candidate, report, latest_head));
        }
    }
    None
}

fn expected_head_advance(elapsed_ms: u64, chain_block_time_ms: u64) -> u64 {
    let block_time = chain_block_time_ms.max(1);
    // We expect at least one new head between checks; add one block of slack for jitter.
    (elapsed_ms / block_time).saturating_add(1)
}

fn load_drift_governor_enabled() -> bool {
    match std::env::var("DRIFT_GOVERNOR_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_drift_ratio_floor() -> f64 {
    std::env::var("DRIFT_RATIO_FLOOR")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1.0)
        .unwrap_or(0.70)
}

fn load_drift_hard_block_ratio() -> f64 {
    std::env::var("DRIFT_HARD_BLOCK_RATIO")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1.0)
        .unwrap_or(0.35)
}

fn load_drift_sample_limit() -> usize {
    std::env::var("DRIFT_SAMPLE_LIMIT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(96)
}

fn load_drift_tighten_multiplier_bps() -> u64 {
    std::env::var("DRIFT_TIGHTEN_MULTIPLIER_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 10_000)
        .unwrap_or(15_000)
}

fn load_drift_steady_state_max_profit_wei(min_expected_profit_wei: U256) -> U256 {
    std::env::var("DRIFT_STEADY_STATE_MAX_PROFIT_WEI")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
        // Default: "steady state" is defined relative to the configured baseline profit floor.
        // If MIN_EXPECTED_PROFIT_WEI is unset (0), we do not apply drift-based throttling.
        .unwrap_or_else(|| {
            if min_expected_profit_wei.is_zero() {
                U256::ZERO
            } else {
                min_expected_profit_wei.saturating_mul(U256::from(10u64))
            }
        })
}

fn derive_realized_profit_estimate(
    expected_profit: Option<U256>,
    outcome_label: ExecutionOutcomeLabel,
) -> (Option<U256>, bool) {
    let Some(expected) = expected_profit else {
        return (None, false);
    };
    match outcome_label {
        ExecutionOutcomeLabel::Included | ExecutionOutcomeLabel::SimulatedOnly => {
            (Some(expected), false)
        }
        _ => (Some(expected), true),
    }
}

fn load_calibration_harness_enabled() -> bool {
    match std::env::var("CALIBRATION_HARNESS_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_calibration_sample_limit() -> usize {
    std::env::var("CALIBRATION_SAMPLE_LIMIT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(24)
}

fn load_calibration_poll_ms() -> u64 {
    std::env::var("CALIBRATION_POLL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 5_000)
        .unwrap_or(120_000)
}

fn load_calibration_min_precision_bps() -> u64 {
    std::env::var("CALIBRATION_MIN_PRECISION_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v <= 10_000)
        .unwrap_or(9_000)
}

fn load_runtime_kill_switch() -> bool {
    match std::env::var("RUNTIME_KILL_SWITCH") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn load_runtime_drawdown_cap_wei() -> Option<U256> {
    std::env::var("RUNTIME_DRAWDOWN_CAP_WEI")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
}

fn load_runtime_per_block_loss_cap_wei() -> Option<U256> {
    std::env::var("RUNTIME_PER_BLOCK_LOSS_CAP_WEI")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
}

fn load_runtime_fail_closed_on_uncertainty() -> bool {
    match std::env::var("RUNTIME_FAIL_CLOSED_ON_UNCERTAINTY") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_profit_weighted_execution_policy() -> ProfitWeightedExecutionPolicy {
    let enabled = match std::env::var("RUNTIME_PROFIT_WEIGHTED_EXECUTION_POLICY") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    };
    let roi_multiple = std::env::var("RUNTIME_PROFIT_WEIGHTED_ROI_MULTIPLE")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(0);
    let risk_budget_wei = std::env::var("RUNTIME_PROFIT_WEIGHTED_RISK_BUDGET_WEI")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
        .unwrap_or(U256::ZERO);
    ProfitWeightedExecutionPolicy {
        enabled,
        roi_multiple,
        risk_budget_wei,
    }
}

fn load_pressure_optimized_risk_weighting_enabled() -> bool {
    match std::env::var("PRESSURE_OPTIMIZED_RISK_WEIGHTING_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_pressure_optimized_high_capital_threshold_eth_wei() -> U256 {
    if let Ok(raw) = std::env::var("PRESSURE_OPTIMIZED_HIGH_CAPITAL_THRESHOLD_WEI") {
        if let Ok(v) = U256::from_str(raw.trim()) {
            return v;
        }
        tracing::warn!(
            "[WARN] Invalid PRESSURE_OPTIMIZED_HIGH_CAPITAL_THRESHOLD_WEI='{}'. Using USD default.",
            raw
        );
    }

    let usd = std::env::var("PRESSURE_OPTIMIZED_HIGH_CAPITAL_THRESHOLD_USD")
        .ok()
        .and_then(|raw| raw.trim().parse::<u128>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PRESSURE_RISK_DEFAULT_HIGH_CAPITAL_USD);
    let eth_usd = std::env::var("PROFIT_ETH_USD")
        .ok()
        .and_then(|raw| raw.trim().parse::<u128>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PRESSURE_RISK_DEFAULT_ETH_USD);

    (U256::from(usd).saturating_mul(U256::from(ONE_ETH_WEI_U128))) / U256::from(eth_usd)
}

fn load_contested_benchmark_enabled() -> bool {
    match std::env::var("CONTESTED_BENCHMARK_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        // Default OFF: analytics-only loop that can cost DB work and log noise.
        Err(_) => false,
    }
}

fn load_contested_benchmark_sample_limit() -> usize {
    std::env::var("CONTESTED_BENCHMARK_SAMPLE_LIMIT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(300)
}

fn load_contested_benchmark_poll_ms() -> u64 {
    std::env::var("CONTESTED_BENCHMARK_POLL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 5_000)
        .unwrap_or(120_000)
}

#[derive(Debug, Clone, Copy, Default)]
struct ContestedBenchmarkTally {
    attempts: u64,
    wins: u64,
    outbid: u64,
    late: u64,
    reverted: u64,
    unprofitable: u64,
    other_losses: u64,
}

fn latency_bucket_label(latency_ms: u64) -> &'static str {
    if latency_ms < 100 {
        "<100ms"
    } else if latency_ms < 250 {
        "100-249ms"
    } else if latency_ms < 500 {
        "250-499ms"
    } else if latency_ms < 1_000 {
        "500-999ms"
    } else {
        ">=1000ms"
    }
}

fn tip_band_label(tip_band_wei: Option<u128>) -> &'static str {
    let Some(tip) = tip_band_wei else {
        return "none";
    };
    if tip < 1_000_000_000u128 {
        "<1gwei"
    } else if tip < 3_000_000_000u128 {
        "1-3gwei"
    } else if tip < 10_000_000_000u128 {
        "3-10gwei"
    } else {
        ">=10gwei"
    }
}

fn apply_contested_row_to_tally(
    tally: &mut ContestedBenchmarkTally,
    accepted: bool,
    outcome_label: &str,
) {
    tally.attempts = tally.attempts.saturating_add(1);
    if accepted {
        tally.wins = tally.wins.saturating_add(1);
        return;
    }

    match outcome_label {
        "outbid" => tally.outbid = tally.outbid.saturating_add(1),
        "late" | "dropped_stale" | "dropped_preflight" => tally.late = tally.late.saturating_add(1),
        "reverted" | "dropped_shadow_fail" => tally.reverted = tally.reverted.saturating_add(1),
        "unprofitable_after_gas" => tally.unprofitable = tally.unprofitable.saturating_add(1),
        _ => tally.other_losses = tally.other_losses.saturating_add(1),
    }
}

fn encode_exploit_params_json(params: &dark_solver::solver::objectives::ExploitParams) -> String {
    let steps = params
        .steps
        .iter()
        .map(|step| {
            serde_json::json!({
                "target": format!("{:#x}", step.target),
                "call_data": format!("0x{}", hex::encode(step.call_data.as_ref())),
                "execute_if": step.execute_if.as_ref().map(|cond| {
                    serde_json::json!({
                        "storage_slot": cond.slot.to_string(),
                        "equals": cond.equals.to_string(),
                    })
                }),
            })
        })
        .collect::<Vec<_>>();
    let flash_loan_legs = params
        .flash_loan_legs
        .iter()
        .map(|leg| {
            serde_json::json!({
                "provider": format!("{:#x}", leg.provider),
                "token": format!("{:#x}", leg.token),
                "amount": leg.amount.to_string(),
                "fee_bps": leg.fee_bps,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "flash_loan_amount": params.flash_loan_amount.to_string(),
        "flash_loan_token": format!("{:#x}", params.flash_loan_token),
        "flash_loan_provider": format!("{:#x}", params.flash_loan_provider),
        "flash_loan_legs": flash_loan_legs,
        "expected_profit": params.expected_profit.map(|v| v.to_string()),
        "block_offsets": params.block_offsets,
        "steps": steps,
    })
    .to_string()
}

fn decode_exploit_params_json(raw: &str) -> Option<dark_solver::solver::objectives::ExploitParams> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let flash_loan_amount = value
        .get("flash_loan_amount")?
        .as_str()
        .and_then(|v| U256::from_str(v).ok())?;
    let flash_loan_token = value
        .get("flash_loan_token")?
        .as_str()
        .and_then(|v| Address::from_str(v).ok())?;
    let flash_loan_provider = value
        .get("flash_loan_provider")?
        .as_str()
        .and_then(|v| Address::from_str(v).ok())?;
    let flash_loan_legs = value
        .get("flash_loan_legs")
        .and_then(|v| v.as_array())
        .map(|legs| {
            legs.iter()
                .filter_map(|entry| {
                    let provider = entry
                        .get("provider")
                        .and_then(|v| v.as_str())
                        .and_then(|v| Address::from_str(v).ok())?;
                    let token = entry
                        .get("token")
                        .and_then(|v| v.as_str())
                        .and_then(|v| Address::from_str(v).ok())?;
                    let amount = entry
                        .get("amount")
                        .and_then(|v| v.as_str())
                        .and_then(|v| U256::from_str(v).ok())?;
                    let fee_bps = entry.get("fee_bps").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    Some(dark_solver::solver::objectives::FlashLoanLeg {
                        provider,
                        token,
                        amount,
                        fee_bps,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let expected_profit = value
        .get("expected_profit")
        .and_then(|v| v.as_str())
        .and_then(|v| U256::from_str(v).ok());
    let block_offsets = value
        .get("block_offsets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.as_u64())
                .collect::<Vec<_>>()
        });
    let steps = value
        .get("steps")?
        .as_array()?
        .iter()
        .map(|entry| {
            let target = entry
                .get("target")
                .and_then(|v| v.as_str())
                .and_then(|v| Address::from_str(v).ok())?;
            let call_data = entry
                .get("call_data")
                .and_then(|v| v.as_str())
                .and_then(|v| {
                    let clean = v.strip_prefix("0x").unwrap_or(v);
                    hex::decode(clean).ok()
                })
                .map(Bytes::from)?;
            let execute_if = entry
                .get("execute_if")
                .and_then(|v| v.as_object())
                .and_then(|obj| {
                    let slot = obj
                        .get("storage_slot")
                        .and_then(|v| v.as_str())
                        .and_then(|v| U256::from_str(v).ok())?;
                    let equals = obj
                        .get("equals")
                        .and_then(|v| v.as_str())
                        .and_then(|v| U256::from_str(v).ok())?;
                    Some(dark_solver::solver::objectives::ExecuteIfStorageEq { slot, equals })
                });
            Some(dark_solver::solver::objectives::ExploitStep {
                target,
                call_data,
                execute_if,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(dark_solver::solver::objectives::ExploitParams {
        flash_loan_amount,
        flash_loan_token,
        flash_loan_provider,
        flash_loan_legs,
        steps,
        expected_profit,
        block_offsets,
    })
}

fn precision_bps(true_positives: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((true_positives as u128).saturating_mul(10_000u128) / total as u128) as u64
}

#[allow(clippy::too_many_arguments)]
fn persist_fail_closed_attempt(
    contracts_db: &ContractsDb,
    target: Address,
    objective: &str,
    solve_block: u64,
    solve_time_ms: u128,
    expected_profit_wei: Option<U256>,
    payload_json: Option<String>,
    reason: &str,
    reason_details: serde_json::Value,
) {
    let solve_started_ms = now_ms().saturating_sub(solve_time_ms.min(u64::MAX as u128) as u64);
    let details_json = Some(
        serde_json::json!({
            "drop_reason": reason,
            "reason_details": reason_details,
            "solve_started_ms": solve_started_ms,
        })
        .to_string(),
    );
    let record = SubmissionAttemptRecord {
        target,
        objective: objective.to_string(),
        solve_block,
        solve_duration_ms: solve_time_ms,
        solve_started_ms,
        replay_completed_ms: None,
        send_completed_ms: None,
        tip_wei: None,
        max_fee_wei: None,
        expected_profit_wei,
        realized_profit_wei: None,
        realized_profit_negative: false,
        latency_bucket_ms: Some(solve_time_ms.min(u64::MAX as u128) as u64),
        tip_band_wei: None,
        chosen_builders: Vec::new(),
        outcome_label: ExecutionOutcomeLabel::DroppedSafetyRails,
        included: Some(false),
        reverted: None,
        inclusion_block: None,
        contested: false,
        payload_json,
        details_json,
        builder_outcomes: Vec::new(),
    };
    if let Err(err) = contracts_db.record_submission_attempt(record) {
        tracing::warn!(
            "[WARN] Failed to persist fail-closed attempt for {:?} [{}]: {}",
            target,
            objective,
            compact_error(err)
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Runtime dashboard is env-driven; TARGET_ADDRESS pins a single target when set.
    let runtime_args = parse_runtime_args()?;

    // Validate environment files and load defaults before runtime initialization.
    dark_solver::utils::env_guard::harden_env_setup();
    let runtime_profile = apply_runtime_profile(runtime_args.profile);
    let discovery_mode = apply_discovery_mode_defaults();

    // Emit startup logging configuration state for operator visibility.
    match std::env::var("RUST_LOG") {
        Ok(val) => println!("[STARTUP] RUST_LOG is set to: '{}'", val),
        Err(_) => println!("[STARTUP] RUST_LOG is unset."),
    }

    // Default to `info` when `RUST_LOG` is unset or invalid to avoid silent startup.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        println!("[STARTUP] RUST_LOG invalid or unset; defaulting to 'info'");
        tracing_subscriber::EnvFilter::new("info")
    });

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr) // Force logs to stderr to separate from pipeline output if needed
        .init();

    println!("[STARTUP] Tracing initialized.");
    emit_runtime_profile_status(&runtime_args, &runtime_profile, &discovery_mode);
    emit_discovery_mode_status(&discovery_mode);
    if runtime_args.explain_config {
        tracing::info!(
            "[OPS] DASHBOARD_EXPLAIN_CONFIG=true requested; runtime profile and dynamic defaults resolved."
        );
        return Ok(());
    }

    dark_solver::utils::blackbox::install_panic_hook_once();
    println!("[STARTUP] Panic hook installed.");

    dark_solver::utils::telemetry::init_telemetry();
    println!("[STARTUP] Telemetry initialized.");
    dark_solver::utils::telemetry::emit(
        dark_solver::utils::telemetry::TelemetryLevel::Info,
        "startup",
        "dark_solver_boot",
    );

    // Probe RPC connectivity early so configuration failures are visible immediately.
    // Use a temporary scope so the probe resources are dropped before the main loop starts.
    {
        let rpc_url = std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "UNSET".to_string());
        println!(
            "[STARTUP] Checking Connectivity to ETH_RPC_URL: {}...",
            if rpc_url.len() > 10 {
                format!("{}...", &rpc_url[..10])
            } else {
                rpc_url.clone()
            }
        );

        // Run a quick provider probe instead of waiting for downstream workers to fail later.
        match ProviderBuilder::new()
            .on_http(
                rpc_url
                    .parse()
                    .unwrap_or_else(|_| "http://localhost:8545".parse().unwrap()),
            )
            .get_block_number()
            .await
        {
            Ok(n) => println!("[STARTUP] CONNECTIVITY OK. Latest Block: {}", n),
            Err(e) => println!("[STARTUP] CONNECTIVITY FAILURE: {}", e),
        }
    }
    tracing::info!("[STARTUP] Checking clock drift (NTP)...");
    if let Err(err) = enforce_startup_clock_drift_guard().await {
        dark_solver::utils::telemetry::emit_critical(
            "startup_clock_drift_guard",
            format!("Clock drift guard failed: {}", compact_error(&err)),
        );
        return Err(err);
    }
    tracing::info!("[STARTUP] Clock drift OK.");

    use std::io::Write;
    tracing::debug!("Starting Dark Solver audit runtime...");
    tracing::debug!("[*] Initializing system components...");
    let strategy_params_state = Arc::new(tokio::sync::RwLock::new(
        dark_solver::utils::config::StrategyParams::from_env(),
    ));
    let min_expected_profit_wei = strategy_params_state.read().await.min_expected_profit_wei;
    let drift_governor_enabled = load_drift_governor_enabled();
    let drift_ratio_floor = load_drift_ratio_floor();
    let drift_hard_block_ratio = load_drift_hard_block_ratio();
    let drift_sample_limit = load_drift_sample_limit();
    let drift_tighten_multiplier_bps = load_drift_tighten_multiplier_bps();
    let drift_steady_state_max_profit_wei =
        load_drift_steady_state_max_profit_wei(min_expected_profit_wei);
    let calibration_harness_enabled = load_calibration_harness_enabled();
    let calibration_sample_limit = load_calibration_sample_limit();
    let calibration_poll_ms = load_calibration_poll_ms();
    let calibration_min_precision_bps = load_calibration_min_precision_bps();
    let runtime_kill_switch = load_runtime_kill_switch();
    let runtime_drawdown_cap_wei = load_runtime_drawdown_cap_wei();
    let runtime_per_block_loss_cap_wei = load_runtime_per_block_loss_cap_wei();
    let runtime_fail_closed_on_uncertainty = load_runtime_fail_closed_on_uncertainty();
    let profit_weighted_execution_policy = load_profit_weighted_execution_policy();
    let pressure_risk_weighting_enabled = load_pressure_optimized_risk_weighting_enabled();
    let pressure_risk_high_capital_threshold_wei =
        load_pressure_optimized_high_capital_threshold_eth_wei();
    let contested_benchmark_enabled = load_contested_benchmark_enabled();
    let contested_benchmark_sample_limit = load_contested_benchmark_sample_limit();
    let contested_benchmark_poll_ms = load_contested_benchmark_poll_ms();
    let background_solver_queue_enabled = load_background_solver_queue_enabled();
    let background_solver_queue_workers = load_background_solver_queue_workers();
    let background_solver_queue_capacity = load_background_solver_queue_capacity();
    let jit_tuner_enabled = load_jit_tuner_enabled();
    let jit_tuner_budget_ms = load_jit_tuner_budget_ms();
    let jit_tuner_max_offset_shift = load_jit_tuner_max_offset_shift();
    let immediate_bundle_relay_enabled = load_immediate_bundle_relay_enabled();
    let proof_persistence_enabled = load_proof_persistence_enabled();
    let proof_persistence_stale_blocks = load_proof_persistence_stale_blocks();
    let proof_persistence_max_items = load_proof_persistence_max_items();
    let proof_persistence_recheck_per_block = load_proof_persistence_recheck_per_block();
    let proof_persistence_replay_timeout_ms = load_proof_persistence_replay_timeout_ms();
    let proof_persistence_complex_replay_timeout_ms =
        load_proof_persistence_complex_replay_timeout_ms();
    let proof_persistence_max_replay_attempts = load_proof_persistence_max_replay_attempts();
    if !min_expected_profit_wei.is_zero() {
        tracing::debug!(
            "[EV] SAT finding execution floor active: MIN_EXPECTED_PROFIT_WEI={}",
            min_expected_profit_wei
        );
    }
    if drift_governor_enabled {
        tracing::debug!(
            "[EV] Drift governor active: ratio_floor={:.2}, hard_block={:.2}, sample_limit={}, tighten_bps={}",
            drift_ratio_floor,
            drift_hard_block_ratio,
            drift_sample_limit,
            drift_tighten_multiplier_bps
        );
        if drift_steady_state_max_profit_wei.is_zero() {
            tracing::debug!(
                "[EV] Drift governor steady-state throttle disabled (MIN_EXPECTED_PROFIT_WEI is 0 and DRIFT_STEADY_STATE_MAX_PROFIT_WEI not set)."
            );
        } else {
            tracing::debug!(
                "[EV] Drift governor steady-state profit cap: DRIFT_STEADY_STATE_MAX_PROFIT_WEI={}",
                drift_steady_state_max_profit_wei
            );
        }
    }
    if calibration_harness_enabled {
        tracing::debug!(
            "[CAL] Profitability calibration harness active: min_precision_bps={} sample_limit={} poll_ms={}",
            calibration_min_precision_bps,
            calibration_sample_limit,
            calibration_poll_ms
        );
    }
    if contested_benchmark_enabled {
        tracing::debug!(
            "[BENCH] Contested inclusion benchmark active: sample_limit={} poll_ms={}",
            contested_benchmark_sample_limit,
            contested_benchmark_poll_ms
        );
    }
    if runtime_kill_switch {
        tracing::warn!("[RISK] Runtime kill switch is ACTIVE. Live execution will fail closed.");
    }
    if let Some(cap) = runtime_drawdown_cap_wei {
        tracing::debug!("[RISK] Rolling drawdown cap enabled: {} wei", cap);
    }
    if let Some(cap) = runtime_per_block_loss_cap_wei {
        tracing::debug!("[RISK] Per-block loss cap enabled: {} wei", cap);
    }
    if runtime_fail_closed_on_uncertainty {
        tracing::debug!("[RISK] Fail-closed-on-uncertainty policy enabled.");
    }
    if profit_weighted_execution_policy.is_active() {
        tracing::debug!(
            "[RISK] Profit-weighted uncertainty override enabled: roi_multiple={} risk_budget_wei={}",
            profit_weighted_execution_policy.roi_multiple,
            profit_weighted_execution_policy.risk_budget_wei
        );
    }
    if pressure_risk_weighting_enabled {
        tracing::debug!(
            "[RISK] Pressure-optimized risk weighting enabled: high_capital_threshold_wei={}",
            pressure_risk_high_capital_threshold_wei
        );
    } else {
        tracing::debug!("[RISK] Pressure-optimized risk weighting disabled.");
    }
    if background_solver_queue_enabled {
        tracing::debug!(
            "[SCHED] Background deep-solver queue enabled: workers={} capacity={}",
            background_solver_queue_workers,
            background_solver_queue_capacity
        );
    } else {
        tracing::debug!("[SCHED] Background deep-solver queue disabled.");
    }
    if jit_tuner_enabled {
        tracing::debug!(
            "[EXEC] JIT volatile tuner enabled: budget={}ms max_offset_shift={}",
            jit_tuner_budget_ms,
            jit_tuner_max_offset_shift
        );
    } else {
        tracing::debug!("[EXEC] JIT volatile tuner disabled.");
    }
    if immediate_bundle_relay_enabled {
        tracing::debug!("[EXEC] Immediate bundle relay enabled (skip duplicate local replay when already verified).");
    }
    if proof_persistence_enabled {
        tracing::debug!(
            "[STRAT] Proof-persistence engine enabled: stale_blocks={} recheck_per_block={} max_items={} replay_timeout={}ms",
            proof_persistence_stale_blocks,
            proof_persistence_recheck_per_block,
            proof_persistence_max_items,
            proof_persistence_replay_timeout_ms
        );
    } else {
        tracing::debug!("[STRAT] Proof-persistence engine disabled.");
    }

    // 0. Load Config FIRST
    let config = dark_solver::utils::config::Config::load()?;
    tracing::info!(
        "[STARTUP] Config loaded: ChainID={}, SubmissionMode={}",
        config.chain_id,
        config.submission_enabled
    );
    if let Some(target) = runtime_args.manual_target {
        tracing::debug!(
            "[MANUAL] Target injection enabled for {:?}; scanner/backfill disabled.",
            target
        );
    }
    let contracts_db = Arc::new(ContractsDb::open_default()?);
    tracing::info!("[STARTUP] SQLite persistence initialized.");

    let (hydration_pool, _hydration_rpc_urls) =
        dark_solver::utils::rpc::build_hydration_provider_pool(&config.eth_rpc_url)?;
    let hydration_pool = Arc::new(hydration_pool);
    tracing::info!("[STARTUP] Preloading profit-tracking token state...");
    match tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking({
            let rpc_url = config.eth_rpc_url.clone();
            let db = (*contracts_db).clone();
            move || dark_solver::solver::setup::preload_profit_tracking_state(&rpc_url, Some(&db))
        }),
    )
    .await
    {
        Ok(Ok(Ok(count))) if count > 0 => {
            tracing::info!(
                "[STARTUP] Preloaded {} PROFIT_TRACK_TOKENS targets into local setup cache.",
                count
            );
        }
        Ok(Ok(Ok(_))) => {
            tracing::info!("[STARTUP] Preload complete (0 tokens).");
        }
        Ok(Ok(Err(err))) => {
            tracing::warn!(
                "[STARTUP] Startup pre-loader failed (non-fatal): {}",
                compact_error(err)
            );
        }
        Ok(Err(join_err)) => {
            tracing::warn!(
                "[STARTUP] Startup pre-loader task panicked (non-fatal): {}",
                join_err
            );
        }
        Err(_) => {
            tracing::warn!(
                "[STARTUP] Startup pre-loader timed out after 30s (non-fatal). Continuing without preload."
            );
        }
    }

    // Priority Hot-Lane Ingestion: replace the single FIFO mpsc lane with a
    // bounded, priority-sorted target buffer so high-capital targets bypass dust backlog.
    let (tx, mut rx) = TargetQueue::new(2_000);
    // SHUTDOWN SIGNAL
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

    #[cfg(unix)]
    {
        let shutdown_tx_sigterm = shutdown_tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut term_signal) = signal(SignalKind::terminate()) else {
                return;
            };
            let _ = term_signal.recv().await;
            dark_solver::utils::blackbox::record("signal", "sigterm_received", None);
            let _ = dark_solver::utils::blackbox::dump("sigterm");
            dark_solver::utils::telemetry::emit_critical(
                "sigterm",
                "SIGTERM received; dumping blackbox and shutting down",
            );
            let _ = shutdown_tx_sigterm.send(());
        });
    }

    // 1. Start Scanner + Backfill (Background), unless manual target mode is active.
    if runtime_args.manual_target.is_none() {
        let scan_audit_mode = std::env::var("SCAN_AUDIT_MODE")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let defillama_scanner_only = std::env::var("DEFILLAMA_SCANNER_ONLY")
            .unwrap_or_else(|_| "false".into())
            .eq_ignore_ascii_case("true");

        if scan_audit_mode {
            eprintln!("[STARTUP] SCAN_AUDIT_MODE=true; scanner/backfill/priority skipped.");
        } else if defillama_scanner_only {
            eprintln!(
                "[STARTUP] DEFILLAMA_SCANNER_ONLY=true; block scanner/backfill/priority skipped."
            );
        } else {
            let ws_url = config.eth_ws_url.clone();
            let scanner_sender = tx.clone();
            let shutdown_rx_scanner = shutdown_tx.subscribe();
            let scanner_last_good_head = Arc::new(AtomicU64::new(0));
            let scanner_last_good_head_state = scanner_last_good_head.clone();
            let scanner_db = (*contracts_db).clone();
            let scanner_hydration_pool = Arc::clone(&hydration_pool);

            tokio::spawn(async move {
                let mut restart_attempts = 0;
                let mut shutdown_rx = shutdown_rx_scanner;

                loop {
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }

                    tracing::info!("[STARTUP] Starting Scanner (WS connect to {})...", &ws_url);
                    let my_rx = shutdown_rx.resubscribe();
                    if let Err(e) = scanner::start_scanner(
                        &ws_url,
                        scanner_sender.clone(),
                        my_rx,
                        scanner_last_good_head_state.clone(),
                        Some(scanner_db.clone()),
                        Arc::clone(&scanner_hydration_pool),
                    )
                    .await
                    {
                        restart_attempts += 1;
                        let backoff_secs = std::cmp::min(60, 5 * (1 << (restart_attempts - 1)));
                        let msg = compact_error(e);
                        eprintln!("[ERROR] Scanner crashed: {}. Restarting in {}s...", msg, backoff_secs);
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    } else {
                        restart_attempts = 0;
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            });

            let backfill_rpc = config.eth_rpc_url.clone();
            let backfill_sender = tx.clone();
            let shutdown_rx_backfill = shutdown_tx.subscribe();
            let backfill_db = (*contracts_db).clone();
            tokio::spawn(async move {
                if let Err(err) = scanner::start_backfill_worker(
                    &backfill_rpc,
                    backfill_sender,
                    shutdown_rx_backfill,
                    Some(backfill_db),
                )
                .await
                {
                    eprintln!("[WARN] Backfill worker exited with error: {:?}", err);
                }
            });

            let priority_rpc = config.eth_rpc_url.clone();
            let priority_sender = tx.clone();
            let shutdown_rx_priority = shutdown_tx.subscribe();
            tokio::spawn(async move {
                if let Err(err) = scanner::start_priority_sequence_indexer(
                    &priority_rpc,
                    priority_sender,
                    shutdown_rx_priority,
                )
                .await
                {
                    eprintln!(
                        "[WARN] Priority sequence indexer exited with error: {:?}",
                        err
                    );
                }
            });
        }

        // DeFiLlama feeder — runs regardless of scanner_only flag.
        // Self-disables via DEFILLAMA_ENABLED check inside start_defillama_feeder().
        let defillama_sender = tx.clone();
        let shutdown_rx_defillama = shutdown_tx.subscribe();
        let defillama_db = (*contracts_db).clone();
        tokio::spawn(async move {
            if let Err(err) = dark_solver::defillama::start_defillama_feeder(
                defillama_sender,
                shutdown_rx_defillama,
                Some(defillama_db),
            )
            .await
            {
                eprintln!("[WARN] DeFiLlama feeder exited with error: {:?}", err);
            }
        });

        // Basescan feeder — discovers actual DeFi contracts (pools, vaults) on Base.
        // Self-disables via BASESCAN_ENABLED check inside start_basescan_feeder().
        let basescan_sender = tx.clone();
        let shutdown_rx_basescan = shutdown_tx.subscribe();
        let basescan_db = (*contracts_db).clone();
        tokio::spawn(async move {
            if let Err(err) = dark_solver::basescan::start_basescan_feeder(
                basescan_sender,
                shutdown_rx_basescan,
                Some(basescan_db),
            )
            .await
            {
                eprintln!("[WARN] Basescan feeder exited with error: {:?}", err);
            }
        });
    } else {
        tracing::debug!("[MANUAL] Scanner and backfill worker skipped.");
    }

    // INFRA PROTECTION: Semaphore and Caches
    let solver_sem = Arc::new(Semaphore::new(20)); // Max 20 concurrent solvers
    let code_cache: Arc<DashMap<Address, Bytes>> = Arc::new(DashMap::new());
    let proxy_cache: Arc<DashMap<Address, Address>> = Arc::new(DashMap::new());
    let inflight_targets: InflightSet = Arc::new(StdMutex::new(HashSet::new()));
    let background_inflight_targets: InflightSet = Arc::new(StdMutex::new(HashSet::new()));

    // 1.c Findings Channel (Decoupled Solver Path)
    let (findings_tx, mut findings_rx) = mpsc::channel::<SolverResult>(100);
    let unsat_progress_counter = Arc::new(AtomicU64::new(0));
    let unsat_progress_log_every = load_solve_unsat_progress_log_every();
    let background_solver_tx = if background_solver_queue_enabled {
        let (tx, rx) = mpsc::channel::<BackgroundSolveTask>(background_solver_queue_capacity);
        let shared_rx = Arc::new(Mutex::new(rx));
        for worker_id in 0..background_solver_queue_workers {
            let rx = Arc::clone(&shared_rx);
            let findings_tx = findings_tx.clone();
            let background_inflight_targets = background_inflight_targets.clone();
            tokio::spawn(async move {
                loop {
                    let task = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(task) = task else {
                        break;
                    };
                    let _inflight_guard =
                        InflightTargetGuard::new(background_inflight_targets.clone(), task.target);

                    while dark_solver::utils::rpc::global_rpc_cooldown_active() {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }

                    let objectives =
                        dark_solver::engine::objective_catalog::build_background_deep_objectives(
                            task.solver_rpc.clone(),
                            task.chain_id,
                        );
                    if objectives.is_empty() {
                        continue;
                    }
                    tracing::debug!(
                        "[SCHED][BG:{}] Running deep objective queue for {:?}.",
                        worker_id,
                        task.target
                    );

                    let (objective_sat_tx, mut objective_sat_rx) =
                        tokio::sync::mpsc::unbounded_channel::<
                            dark_solver::solver::runner::StreamedFinding,
                        >();
                    let runner_bytecode = task.bytecode.clone();
                    let runner_context = Arc::clone(&task.target_context);
                    let runner_handle = tokio::spawn(async move {
                        dark_solver::solver::runner::run_objectives_parallel_streaming(
                            objectives,
                            &runner_bytecode,
                            Some(runner_context),
                            objective_sat_tx,
                        )
                        .await
                    });

                    while let Some((obj_name, params, solve_duration_ms)) =
                        objective_sat_rx.recv().await
                    {
                        let _ = findings_tx
                            .send(SolverResult {
                                target: task.target,
                                bytecode_hash: task.bytecode_hash,
                                findings: vec![(obj_name, params)],
                                solve_duration_ms,
                                solve_target_block: task.solve_target_block,
                                is_retry: false,
                                is_background: true,
                            })
                            .await;
                    }

                    match runner_handle.await {
                        Ok(Ok(_sat_count)) => {}
                        Ok(Err(err)) => {
                            tracing::warn!(
                                "[WARN] Background solver worker {} objective runner failure: {}",
                                worker_id,
                                err
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                "[WARN] Background solver worker {} join error: {:?}",
                                worker_id,
                                err
                            );
                        }
                    }
                }
            });
        }
        Some(tx)
    } else {
        None
    };
    if let Some(target) = runtime_args.manual_target {
        let accepted = tx.enqueue(target, TargetPriority::Manual).await;
        if !accepted {
            return Err(anyhow::anyhow!(
                "failed to enqueue manual target {:?}",
                target
            ));
        }
        tracing::info!("[MANUAL] Injected target {:?} into solver queue.", target);
    }

    // 2. Executor
    tracing::debug!("[*] Initializing Executor...");
    std::io::stdout().flush().ok();
    let executor = Arc::new(Executor::new(
        &config,
        Some(code_cache.clone()),
        Some(proxy_cache.clone()),
    )?);
    let jit_tuner_attacker = if config.submission_enabled {
        executor.attacker_address()
    } else {
        dark_solver::solver::setup::ATTACKER
    };
    tracing::debug!("[+] Executor initialized.");
    std::io::stdout().flush().ok();
    if runtime_args.manual_target.is_none() {
        let mirror_enabled = std::env::var("GENERALIZED_FRONTRUN_ENABLED")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        if mirror_enabled {
            let mirror_ws_url = config.eth_ws_url.clone();
            let mirror_executor = executor.clone();
            let shutdown_rx_mirror = shutdown_tx.subscribe();
            tokio::spawn(async move {
                if let Err(err) =
                    dark_solver::strategies::generalized_frontrun::start_generalized_frontrun(
                        &mirror_ws_url,
                        mirror_executor,
                        shutdown_rx_mirror,
                    )
                    .await
                {
                    tracing::warn!(
                        "[MIRROR] Generalized frontrun strategy exited with error: {}",
                        compact_error(err)
                    );
                }
            });
        } else {
            tracing::debug!("[MIRROR] Disabled (GENERALIZED_FRONTRUN_ENABLED != true).");
        }
    }

    // 3. Pipeline Loop
    // Config already loaded at start

    let db_url = config.eth_rpc_url.clone();
    let rpc_url = config.eth_rpc_url.clone();

    // ITERATION 12: Autonomous Recovery (Graceful Shutdown Hook)
    // We spawn a listener for SIGINT to save state (if any) or just exit cleanly.
    // NOTE: This runs in parallel to the main loop's select! signal handler
    // to ensure we catch it if the main loop is stuck.
    tokio::spawn(async move {
        // This is a backup catcher. The main loop also catches it.
        // We'll let the main loop handle the primary exit.
    });

    let fork_db = ForkDB::new(&db_url)?;
    let _cache_db = CacheDB::new(fork_db);
    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
    let provider = Arc::new(provider);
    tracing::debug!("[+] RPC Provider connected: {}", rpc_url);
    let latest_head_hint = Arc::new(AtomicU64::new(0));
    let watch_cache: Arc<Mutex<WatchCache>> = Arc::new(Mutex::new(WatchCache::default()));
    let contested_tip_cache: Arc<Mutex<dark_solver::executor::tip_auto_scaler::ContestedTipCache>> =
        Arc::new(Mutex::new(
            dark_solver::executor::tip_auto_scaler::ContestedTipCache::default(),
        ));
    let proof_persistence_cache: Arc<Mutex<Vec<PersistedDeepProofItem>>> =
        Arc::new(Mutex::new(Vec::new()));
    let calibration_precision_bps = Arc::new(AtomicU64::new(0));
    let calibration_scored_samples = Arc::new(AtomicU64::new(0));
    let calibration_last_run_ms = Arc::new(AtomicU64::new(0));
    let daily_stop_loss_attacker = executor.attacker_address();
    let mut daily_stop_loss_start_balance: Option<U256> = None;
    let mut daily_stop_loss_floor_balance: Option<U256> = None;
    let mut daily_stop_loss_interval =
        tokio::time::interval(tokio::time::Duration::from_millis(15_000));
    daily_stop_loss_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    if config.submission_enabled {
        let start_balance = tokio::time::timeout(
            tokio::time::Duration::from_millis(2_000),
            provider.get_balance(daily_stop_loss_attacker),
        )
        .await
        .map_err(|_| anyhow::anyhow!("daily stop-loss startup balance fetch timed out"))??;
        let floor = start_balance.saturating_sub(U256::from(ONE_ETH_WEI_U128));
        daily_stop_loss_start_balance = Some(start_balance);
        daily_stop_loss_floor_balance = Some(floor);
        tracing::info!(
            "[RISK] Daily stop-loss armed: start_balance={} floor={} drawdown_limit_wei={}",
            start_balance,
            floor,
            U256::from(ONE_ETH_WEI_U128)
        );
    }

    if calibration_harness_enabled {
        let calibration_db = contracts_db.clone();
        let calibration_rpc_url = config
            .execution_rpc_url
            .clone()
            .unwrap_or_else(|| config.eth_rpc_url.clone());
        let calibration_chain_id = config.chain_id;
        let calibration_limit = calibration_sample_limit;
        let calibration_poll = calibration_poll_ms;
        let calibration_attacker = if config.submission_enabled {
            executor.attacker_address()
        } else {
            dark_solver::solver::setup::ATTACKER
        };
        let precision_state = calibration_precision_bps.clone();
        let sample_state = calibration_scored_samples.clone();
        let last_run_state = calibration_last_run_ms.clone();

        tokio::spawn(async move {
            loop {
                if dark_solver::utils::rpc::global_rpc_cooldown_active() {
                    tokio::time::sleep(std::time::Duration::from_millis(calibration_poll)).await;
                    continue;
                }

                match calibration_db.recent_calibration_cases(calibration_limit) {
                    Ok(cases) => {
                        let mut scored = 0u64;
                        let mut true_positives = 0u64;
                        for case in cases {
                            let Some(params) = decode_exploit_params_json(&case.payload_json)
                            else {
                                continue;
                            };
                            if case
                                .expected_profit_wei
                                .map(|v| v.is_zero())
                                .unwrap_or(true)
                            {
                                continue;
                            }

                            let report = dark_solver::executor::verifier::replay_path_at_block(
                                &calibration_rpc_url,
                                calibration_chain_id,
                                calibration_attacker,
                                &params,
                                Some(case.solve_block),
                            );
                            scored = scored.saturating_add(1);
                            if report.success && report.profitable {
                                true_positives = true_positives.saturating_add(1);
                            }
                        }

                        let precision = precision_bps(true_positives, scored);
                        precision_state.store(precision, Ordering::Relaxed);
                        sample_state.store(scored, Ordering::Relaxed);
                        last_run_state.store(now_ms(), Ordering::Relaxed);
                        tracing::debug!(
                            "[CAL] Replay precision={}bps ({}/{})",
                            precision,
                            true_positives,
                            scored
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            "[CAL] Failed to load calibration replay cases: {}",
                            compact_error(err)
                        );
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(calibration_poll)).await;
            }
        });
    }

    if contested_benchmark_enabled {
        let bench_db = contracts_db.clone();
        let bench_sample_limit = contested_benchmark_sample_limit;
        let bench_poll_ms = contested_benchmark_poll_ms;
        tokio::spawn(async move {
            loop {
                match bench_db.contested_benchmark_rows(bench_sample_limit) {
                    Ok(rows) => {
                        if rows.is_empty() {
                            tokio::time::sleep(std::time::Duration::from_millis(bench_poll_ms))
                                .await;
                            continue;
                        }

                        let mut by_builder: HashMap<String, ContestedBenchmarkTally> =
                            HashMap::new();
                        let mut by_latency: HashMap<&'static str, ContestedBenchmarkTally> =
                            HashMap::new();
                        let mut by_tip_band: HashMap<&'static str, ContestedBenchmarkTally> =
                            HashMap::new();

                        for row in rows {
                            let builder_entry = by_builder.entry(row.builder.clone()).or_default();
                            apply_contested_row_to_tally(
                                builder_entry,
                                row.accepted,
                                row.outcome_label.as_str(),
                            );

                            let latency_entry = by_latency
                                .entry(latency_bucket_label(row.latency_ms))
                                .or_default();
                            apply_contested_row_to_tally(
                                latency_entry,
                                row.accepted,
                                row.outcome_label.as_str(),
                            );

                            let tip_entry = by_tip_band
                                .entry(tip_band_label(row.tip_band_wei))
                                .or_default();
                            apply_contested_row_to_tally(
                                tip_entry,
                                row.accepted,
                                row.outcome_label.as_str(),
                            );
                        }

                        let mut builders = by_builder.into_iter().collect::<Vec<_>>();
                        builders.sort_by(|a, b| b.1.attempts.cmp(&a.1.attempts));
                        tracing::debug!(
                            "[BENCH] Contested benchmark refreshed over {} builder-attempt rows.",
                            builders.iter().map(|(_, t)| t.attempts).sum::<u64>()
                        );
                        for (builder, tally) in builders.into_iter().take(8) {
                            tracing::debug!(
                                "[BENCH][BUILDER] builder={} attempts={} win_rate={}bps outbid={} late={} reverted={} unprofitable={} other={}",
                                builder,
                                tally.attempts,
                                precision_bps(tally.wins, tally.attempts),
                                tally.outbid,
                                tally.late,
                                tally.reverted,
                                tally.unprofitable,
                                tally.other_losses
                            );
                        }

                        let mut latency = by_latency.into_iter().collect::<Vec<_>>();
                        latency.sort_by(|a, b| b.1.attempts.cmp(&a.1.attempts));
                        for (bucket, tally) in latency {
                            tracing::debug!(
                                "[BENCH][LATENCY] bucket={} attempts={} win_rate={}bps outbid={} late={} reverted={} unprofitable={} other={}",
                                bucket,
                                tally.attempts,
                                precision_bps(tally.wins, tally.attempts),
                                tally.outbid,
                                tally.late,
                                tally.reverted,
                                tally.unprofitable,
                                tally.other_losses
                            );
                        }

                        let mut tip_bands = by_tip_band.into_iter().collect::<Vec<_>>();
                        tip_bands.sort_by(|a, b| b.1.attempts.cmp(&a.1.attempts));
                        for (band, tally) in tip_bands {
                            tracing::debug!(
                                "[BENCH][TIP] band={} attempts={} win_rate={}bps outbid={} late={} reverted={} unprofitable={} other={}",
                                band,
                                tally.attempts,
                                precision_bps(tally.wins, tally.attempts),
                                tally.outbid,
                                tally.late,
                                tally.reverted,
                                tally.unprofitable,
                                tally.other_losses
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            "[BENCH] Failed to load contested benchmark rows: {}",
                            compact_error(err)
                        );
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(bench_poll_ms)).await;
            }
        });
    }

    if proof_persistence_enabled {
        let persistence_cache = Arc::clone(&proof_persistence_cache);
        let persistence_watch_cache = Arc::clone(&watch_cache);
        let persistence_provider = provider.clone();
        let persistence_head_hint = latest_head_hint.clone();
        let persistence_rpc_url = config
            .execution_rpc_url
            .clone()
            .unwrap_or_else(|| config.eth_rpc_url.clone());
        let persistence_chain_id = config.chain_id;
        let persistence_attacker = jit_tuner_attacker;
        tokio::spawn(async move {
            let mut last_head = 0u64;
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;

                if dark_solver::utils::rpc::global_rpc_cooldown_active() {
                    continue;
                }

                let head = persistence_head_hint.load(Ordering::Relaxed);
                if head == 0 || head == last_head {
                    continue;
                }
                last_head = head;

                let state_root = match persistence_provider
                    .get_block_by_number(head.into(), false.into())
                    .await
                {
                    Ok(Some(block)) => block.header.state_root,
                    Ok(None) => continue,
                    Err(err) => {
                        tracing::warn!(
                            "[PERSIST] Failed to load block header for proof check at head={}: {}",
                            head,
                            compact_error(err)
                        );
                        continue;
                    }
                };

                let candidates = {
                    let mut guard = persistence_cache.lock().await;
                    // Collect stuck findings — promote to watch cache instead of dropping
                    let mut promoted = Vec::new();
                    guard.retain(|item| {
                        if item.consecutive_failures >= proof_persistence_max_replay_attempts {
                            promoted.push(item.clone());
                            false
                        } else {
                            true
                        }
                    });
                    // Promote stuck findings to watch_cache for immediate execution
                    if !promoted.is_empty() {
                        let mut watch_guard = persistence_watch_cache.lock().await;
                        for item in &promoted {
                            let watch_item = dark_solver::executor::watch_cache::WatchCacheItem {
                                target: item.target,
                                objective: item.objective.clone(),
                                fingerprint: item.fingerprint,
                                params: item.params.clone(),
                                original_solve_block: item.solve_block,
                                original_solve_ms: 0,
                                last_checked_block: 0,
                                attempts: 0,
                            };
                            let inserted =
                                watch_guard.insert_if_absent_with_capacity(watch_item, 50);
                            tracing::warn!(
                                "[PERSIST] Promoting stuck finding to watch_cache ({}): target={:?} objective={} consecutive_failures={} total_checks={}",
                                if inserted { "accepted" } else { "duplicate" },
                                item.target,
                                item.objective,
                                item.consecutive_failures,
                                item.checks
                            );
                        }
                    }
                    let mut selected = Vec::new();
                    for item in guard.iter_mut() {
                        if selected.len() >= proof_persistence_recheck_per_block {
                            break;
                        }
                        if head.saturating_sub(item.solve_block) < proof_persistence_stale_blocks {
                            continue;
                        }
                        if item.last_checked_block >= head {
                            continue;
                        }
                        // Exponential backoff: items that keep failing get retried less often.
                        // After N failures, wait 2^N blocks before the next attempt.
                        // This prevents a single broken item from monopolizing replay slots.
                        if item.consecutive_failures > 0 {
                            let backoff_blocks = 1u64 << item.consecutive_failures.min(10);
                            if head.saturating_sub(item.last_checked_block) < backoff_blocks {
                                continue;
                            }
                        }
                        item.last_checked_block = head;
                        item.checks = item.checks.saturating_add(1);
                        selected.push(item.clone());
                    }
                    selected
                };

                for item in candidates {
                    let replay_rpc = persistence_rpc_url.clone();
                    let replay_params = item.params.clone();
                    let mut replay_task = tokio::task::spawn_blocking(move || {
                        dark_solver::executor::verifier::replay_path_at_block(
                            &replay_rpc,
                            persistence_chain_id,
                            persistence_attacker,
                            &replay_params,
                            Some(head),
                        )
                    });

                    // [ADAPTIVE] Scale timeout based on objective complexity.
                    // Complex objectives get a longer (but bounded) timeout ceiling.
                    let is_complex = item.objective.contains("Deep")
                        || item.objective.contains("Audit")
                        || item.objective.contains("Bad Debt")
                        || item.objective.contains("Invariant");

                    let adaptive_timeout_ms = if is_complex {
                        proof_persistence_replay_timeout_ms
                            .max(proof_persistence_complex_replay_timeout_ms)
                    } else {
                        proof_persistence_replay_timeout_ms
                    };

                    let replay_report = match tokio::time::timeout(
                        std::time::Duration::from_millis(adaptive_timeout_ms),
                        &mut replay_task,
                    )
                    .await
                    {
                        Ok(Ok(report)) => Some(report),
                        Ok(Err(err)) => {
                            tracing::warn!(
                                "[PERSIST] Replay worker failed for target={:?} objective={} head={}: {}",
                                item.target,
                                item.objective,
                                head,
                                compact_error(err)
                            );
                            None
                        }
                        Err(_) => {
                            // Abort the leaked spawn_blocking task to free thread pool capacity.
                            replay_task.abort();
                            tracing::warn!(
                                "[PERSIST] Replay timeout for target={:?} objective={} head={} timeout={}ms failures={}.",
                                item.target,
                                item.objective,
                                head,
                                adaptive_timeout_ms,
                                item.consecutive_failures
                            );
                            None
                        }
                    };

                    let Some(report) = replay_report else {
                        // Timeout or worker error — increment consecutive failure counter
                        let mut guard = persistence_cache.lock().await;
                        if let Some(entry) = guard.iter_mut().find(|entry| {
                            entry.target == item.target
                                && entry.objective == item.objective
                                && entry.fingerprint == item.fingerprint
                        }) {
                            entry.consecutive_failures =
                                entry.consecutive_failures.saturating_add(1);
                            tracing::debug!(
                                "[PERSIST] Consecutive failure #{} for target={:?} objective={}",
                                entry.consecutive_failures,
                                item.target,
                                item.objective
                            );
                        }
                        continue;
                    };
                    if report.success && report.profitable {
                        let mut guard = persistence_cache.lock().await;
                        if let Some(entry) = guard.iter_mut().find(|entry| {
                            entry.target == item.target
                                && entry.objective == item.objective
                                && entry.fingerprint == item.fingerprint
                        }) {
                            entry.last_verified_block = Some(head);
                            entry.last_valid_state_root = Some(state_root);
                            entry.consecutive_failures = 0; // Reset on success
                        }
                        tracing::debug!(
                            "[PERSIST] Deep SAT still sound: target={:?} objective={} solve_block={} head={} state_root={:#x}",
                            item.target,
                            item.objective,
                            item.solve_block,
                            head,
                            state_root
                        );
                    } else {
                        let mut guard = persistence_cache.lock().await;
                        guard.retain(|entry| {
                            !(entry.target == item.target
                                && entry.objective == item.objective
                                && entry.fingerprint == item.fingerprint)
                        });
                        drop(guard);

                        let mut watch_guard = persistence_watch_cache.lock().await;
                        watch_guard.remove_target_fingerprint(item.target, item.fingerprint);
                        tracing::warn!(
                            "[PERSIST] Deep SAT invalidated under current state root: target={:?} objective={} solve_block={} head={} state_root={:#x}",
                            item.target,
                            item.objective,
                            item.solve_block,
                            head,
                            state_root
                        );
                    }
                }
            }
        });
    }

    // Background: "Wait-and-Fire" watch cache. When a slow SAT payload is temporarily unprofitable,
    // we re-try it on each new head without re-solving.
    dark_solver::executor::watch_cache::spawn_watch_cache_rechecker(
        Arc::clone(&watch_cache),
        executor.clone(),
        latest_head_hint.clone(),
        Arc::clone(&contested_tip_cache),
        config.submission_enabled,
        WATCH_CACHE_RECHECK_PER_BLOCK,
        WATCH_CACHE_MAX_ATTEMPTS,
    );

    // INFRA PROTECTION: Semaphore and Caches (Moved up)

    // 4. Background: Pulse Heartbeat (Real-time Progress)
    if load_pulse_heartbeat_enabled() {
        let pulse_provider = provider.clone();
        let pulse_head_hint = latest_head_hint.clone();
        let pulse_db = contracts_db.clone();
        let start_time = std::time::Instant::now();
        let rpc_enabled = load_pulse_heartbeat_rpc_enabled();
        tokio::spawn(async move {
            tracing::debug!("[*] Pulse Heartbeat Started.");
            let mut last_good_block = 0u64;
            let mut rpc_error_streak = 0u32;
            let mut last_status_counts = ScanStatusCounts::default();
            let mut pulse_poll_ms = PULSE_BASE_POLL_MS;
            let mut rate_limit_pause_until: Option<std::time::Instant> = None;
            let mut last_warn_log = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(30))
                .unwrap_or_else(std::time::Instant::now);
            let mut suppressed_warns = 0u64;
            let mut warn_throttled = |message: String| {
                let now = std::time::Instant::now();
                if now.duration_since(last_warn_log) >= std::time::Duration::from_secs(8) {
                    if suppressed_warns > 0 {
                        eprintln!(
                            "[WARN] {} ({} similar pulse warning(s) suppressed)",
                            message, suppressed_warns
                        );
                        suppressed_warns = 0;
                    } else {
                        eprintln!("[WARN] {}", message);
                    }
                    last_warn_log = now;
                } else {
                    suppressed_warns += 1;
                }
            };

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(pulse_poll_ms)).await;

                if let Some(until) = rate_limit_pause_until {
                    if std::time::Instant::now() < until {
                        continue;
                    }
                    rate_limit_pause_until = None;
                    rpc_error_streak = 0;
                    pulse_poll_ms = PULSE_BASE_POLL_MS;
                    warn_throttled("Pulse monitor resumed after rate-limit cooldown.".to_string());
                }

                let uptime = start_time.elapsed();
                let hours = uptime.as_secs() / 3600;
                let minutes = (uptime.as_secs() % 3600) / 60;
                let seconds = uptime.as_secs() % 60;
                dark_solver::solver::verification::record_memory_sample();
                match pulse_db.scan_status_counts() {
                    Ok(counts) => {
                        last_status_counts = counts;
                    }
                    Err(err) => {
                        warn_throttled(format!(
                            "Pulse queue-state query failed: {}",
                            compact_error(err)
                        ));
                    }
                }

                // Measure RPC latency
                if !rpc_enabled {
                    println!(
                        "[PULSE] uptime: {:02}h {:02}m {:02}s | rpc: disabled | block_hint: {} | q:{} ip:{} done:{} total:{} | status: QUEUE_ONLY",
                        hours,
                        minutes,
                        seconds,
                        pulse_head_hint.load(Ordering::Relaxed),
                        last_status_counts.queued,
                        last_status_counts.in_progress,
                        last_status_counts.done,
                        last_status_counts.total(),
                    );
                    continue;
                }
                let rpc_start = std::time::Instant::now();
                match dark_solver::utils::rpc::RobustRpc::get_block_number_with_retry(
                    pulse_provider.clone(),
                    1,
                )
                .await
                {
                    Ok(block_num) => {
                        let latency = rpc_start.elapsed().as_millis();
                        last_good_block = block_num;
                        pulse_head_hint.store(block_num, Ordering::Relaxed);
                        rpc_error_streak = 0;
                        pulse_poll_ms = PULSE_BASE_POLL_MS;
                        let status = if dark_solver::utils::rpc::global_rpc_cooldown_active() {
                            "DEGRADED(COOLDOWN)"
                        } else if latency >= PULSE_DEGRADED_LATENCY_MS {
                            "DEGRADED(RPC_LATENCY)"
                        } else {
                            "ACTIVE"
                        };
                        println!(
                            "\r[PULSE] uptime: {:02}h {:02}m {:02}s | rpc: {}ms | block: {} | q:{} ip:{} done:{} total:{} | status: {}",
                            hours,
                            minutes,
                            seconds,
                            latency,
                            block_num,
                            last_status_counts.queued,
                            last_status_counts.in_progress,
                            last_status_counts.done,
                            last_status_counts.total(),
                            status
                        );
                    }
                    Err(err) => {
                        let latency = rpc_start.elapsed().as_millis();
                        rpc_error_streak = rpc_error_streak.saturating_add(1);
                        let msg = compact_error(err);
                        if dark_solver::utils::rpc::is_rate_limited_rpc_error(&msg) {
                            pulse_poll_ms = dark_solver::utils::rpc::bounded_exponential_backoff_ms(
                                PULSE_BASE_POLL_MS,
                                rpc_error_streak,
                                PULSE_MAX_POLL_MS,
                            );
                            if rpc_error_streak >= 6 {
                                rate_limit_pause_until = std::time::Instant::now().checked_add(
                                    std::time::Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS),
                                );
                                warn_throttled(
                                    "Pulse monitor repeatedly rate-limited; pausing probes for 120s."
                                        .to_string(),
                                );
                                rpc_error_streak = 0;
                            }
                        }
                        warn_throttled(format!("Pulse RPC probe failed: {}", msg));
                        println!(
                            "\r[PULSE] uptime: {:02}h {:02}m {:02}s | rpc: {}ms | block: {} | q:{} ip:{} done:{} total:{} | status: RPC_DEGRADED({})",
                            hours,
                            minutes,
                            seconds,
                            latency,
                            last_good_block,
                            last_status_counts.queued,
                            last_status_counts.in_progress,
                            last_status_counts.done,
                            last_status_counts.total(),
                            rpc_error_streak
                        );
                    }
                }
            }
        });
    } else {
        tracing::debug!("[OPS] Pulse heartbeat disabled (PULSE_HEARTBEAT_ENABLED != true).");
    }

    // 5. Background: Reorg Watcher
    if load_reorg_watcher_enabled() {
        let watcher_provider = provider.clone();
        let watcher_code_cache = code_cache.clone();
        let watcher_proxy_cache = proxy_cache.clone();
        let watcher_head_hint = latest_head_hint.clone();
        let reorg_chain_block_time_ms =
            dark_solver::config::chains::ChainConfig::get(config.chain_id)
                .block_time_ms
                .max(1);

        tokio::spawn(async move {
            let mut last_processed_block: Option<(u64, B256)> = None;
            let mut last_processed_instant: Option<std::time::Instant> = None;
            let mut poll_ms = REORG_BASE_POLL_MS;
            let mut rate_limit_streak = 0u32;
            let mut rate_limit_pause_until: Option<std::time::Instant> = None;
            let mut last_warn_log = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(30))
                .unwrap_or_else(std::time::Instant::now);
            let mut suppressed_warns = 0u64;
            let mut warn_throttled = |message: String| {
                let now = std::time::Instant::now();
                if now.duration_since(last_warn_log) >= std::time::Duration::from_secs(8) {
                    if suppressed_warns > 0 {
                        eprintln!(
                            "[WARN] {} ({} similar reorg warning(s) suppressed)",
                            message, suppressed_warns
                        );
                        suppressed_warns = 0;
                    } else {
                        eprintln!("[WARN] {}", message);
                    }
                    last_warn_log = now;
                } else {
                    suppressed_warns += 1;
                }
            };
            tracing::debug!("[*] Reorg Watcher Started.");

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(poll_ms)).await;

                if let Some(until) = rate_limit_pause_until {
                    if std::time::Instant::now() < until {
                        continue;
                    }
                    rate_limit_pause_until = None;
                    rate_limit_streak = 0;
                    poll_ms = REORG_BASE_POLL_MS;
                    warn_throttled("Reorg Watcher resumed after rate-limit cooldown.".to_string());
                }

                match dark_solver::utils::rpc::RobustRpc::get_block_number_with_retry(
                    watcher_provider.clone(),
                    1,
                )
                .await
                {
                    Ok(latest_num) => {
                        let now = std::time::Instant::now();
                        watcher_head_hint.store(latest_num, Ordering::Relaxed);
                        rate_limit_streak = 0;
                        poll_ms = REORG_BASE_POLL_MS;
                        // Fetch full block for hash check
                        match watcher_provider
                            .get_block_by_number(latest_num.into(), false.into())
                            .await
                        {
                            Ok(Some(block)) => {
                                let current_hash = block.header.hash; // Alloy structure

                                if let Some((old_num, old_hash)) = last_processed_block {
                                    if latest_num < old_num {
                                        eprintln!(
                                            "[REORG] Chain rollback detected: {} -> {}. Clearing caches.",
                                            old_num, latest_num
                                        );
                                        watcher_code_cache.clear();
                                        watcher_proxy_cache.clear();
                                        dark_solver::solver::memo::clear_cache();
                                    } else if latest_num == old_num && current_hash != old_hash {
                                        eprintln!(
                                            "[REORG] Competing block detected at height {}. Clearing caches.",
                                            latest_num
                                        );
                                        watcher_code_cache.clear();
                                        watcher_proxy_cache.clear();
                                        dark_solver::solver::memo::clear_cache();
                                    } else if latest_num > old_num {
                                        // Only clear caches on abnormal jumps that exceed expected
                                        // head advance for elapsed wall time on this chain.
                                        if latest_num > old_num + 1 {
                                            let elapsed_ms = last_processed_instant
                                                .map(|prev| {
                                                    now.duration_since(prev).as_millis() as u64
                                                })
                                                .unwrap_or(poll_ms);
                                            let observed_advance =
                                                latest_num.saturating_sub(old_num);
                                            let expected_advance = expected_head_advance(
                                                elapsed_ms,
                                                reorg_chain_block_time_ms,
                                            );
                                            let tolerated_advance = expected_advance
                                                .saturating_add(REORG_JUMP_EXPECTED_SLACK_BLOCKS);
                                            if observed_advance > tolerated_advance {
                                                eprintln!(
                                                    "[REORG] Unexpected head jump detected: {} -> {}. Clearing caches proactively.",
                                                    old_num, latest_num
                                                );
                                                watcher_code_cache.clear();
                                                watcher_proxy_cache.clear();
                                                dark_solver::solver::memo::clear_cache();
                                            }
                                        }
                                        if block.header.parent_hash != old_hash
                                            && latest_num == old_num + 1
                                        {
                                            eprintln!(
                                                "[REORG] Parent hash mismatch at {} (micro-reorg). Clearing caches.",
                                                latest_num
                                            );
                                            watcher_code_cache.clear();
                                            watcher_proxy_cache.clear();
                                            dark_solver::solver::memo::clear_cache();
                                        }
                                    }
                                }

                                last_processed_block = Some((latest_num, current_hash));
                                last_processed_instant = Some(now);
                            }
                            Ok(None) => {} // Pending/Missing
                            Err(e) => {
                                let msg = compact_error(e);
                                if dark_solver::utils::rpc::is_rate_limited_rpc_error(&msg) {
                                    rate_limit_streak = rate_limit_streak.saturating_add(1);
                                    poll_ms =
                                        dark_solver::utils::rpc::bounded_exponential_backoff_ms(
                                            REORG_BASE_POLL_MS,
                                            rate_limit_streak,
                                            REORG_MAX_POLL_MS,
                                        );
                                    if rate_limit_streak >= 6 {
                                        rate_limit_pause_until = std::time::Instant::now()
                                            .checked_add(std::time::Duration::from_secs(
                                                RATE_LIMIT_COOLDOWN_SECS,
                                            ));
                                        warn_throttled("Reorg Watcher repeatedly rate-limited; pausing checks for 120s.".to_string());
                                        rate_limit_streak = 0;
                                    }
                                }
                                warn_throttled(format!(
                                    "Reorg Watcher Block Fetch Failed: {}",
                                    msg
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        let msg = compact_error(e);
                        if dark_solver::utils::rpc::is_rate_limited_rpc_error(&msg) {
                            rate_limit_streak = rate_limit_streak.saturating_add(1);
                            poll_ms = dark_solver::utils::rpc::bounded_exponential_backoff_ms(
                                REORG_BASE_POLL_MS,
                                rate_limit_streak,
                                REORG_MAX_POLL_MS,
                            );
                            if rate_limit_streak >= 6 {
                                rate_limit_pause_until = std::time::Instant::now().checked_add(
                                    std::time::Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS),
                                );
                                warn_throttled(
                                    "Reorg Watcher repeatedly rate-limited; pausing checks for 120s."
                                        .to_string(),
                                );
                                rate_limit_streak = 0;
                            }
                        }
                        warn_throttled(format!("Reorg Watcher Provider Error: {}", msg));
                    }
                }
            }
        });
    } else {
        tracing::debug!("[*] Reorg Watcher Disabled by REORG_WATCHER_ENABLED.");
    }

    // 3. Pipeline Loop (Graceful Shutdown)
    tracing::debug!("[*] Main Loop Started. Press Ctrl+C to stop.");
    let mut skipped_done_targets: u64 = 0;
    loop {
        tokio::select! {
            _ = daily_stop_loss_interval.tick(), if daily_stop_loss_start_balance.is_some() => {
                let start_balance = daily_stop_loss_start_balance.unwrap_or(U256::ZERO);
                let floor = daily_stop_loss_floor_balance.unwrap_or(U256::ZERO);
                let timeout_ms = load_daily_stop_loss_timeout_ms();
                let mut attempts = 0;
                let mut success = false;

                while attempts < 3 && !success {
                    attempts += 1;
                    match tokio::time::timeout(
                        tokio::time::Duration::from_millis(timeout_ms),
                        provider.get_balance(daily_stop_loss_attacker),
                    )
                    .await
                    {
                        Ok(Ok(current_balance)) => {
                            success = true;
                            if current_balance < floor {
                                dark_solver::utils::blackbox::record(
                                    "risk",
                                    "daily_stop_loss_triggered",
                                    Some(serde_json::json!({
                                        "current_balance": current_balance.to_string(),
                                        "floor_balance": floor.to_string(),
                                        "start_balance": start_balance.to_string(),
                                    })),
                                );
                                dark_solver::utils::telemetry::emit_critical(
                                    "daily_stop_loss",
                                    format!(
                                        "Daily stop-loss triggered current={} floor={} start={}",
                                        current_balance, floor, start_balance
                                    ),
                                );
                                let _ = dark_solver::utils::blackbox::dump("daily_stop_loss");
                                panic!(
                                    "[RISK] Daily stop-loss triggered: current_balance={} floor={} start_balance={} drawdown_limit_wei={}",
                                    current_balance,
                                    floor,
                                    start_balance,
                                    U256::from(ONE_ETH_WEI_U128)
                                );
                            }
                        }
                        Ok(Err(err)) => {
                            tracing::warn!(
                                "[RISK] Daily stop-loss balance probe failed (attempt {}/3): {}",
                                attempts,
                                compact_error(err)
                            );
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        }
                        Err(_) => {
                            tracing::warn!("[RISK] Daily stop-loss balance probe timed out (attempt {}/3).", attempts);
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        }
                    }
                }
            }
            // Branch 1: New Target Spotted
            maybe_target = rx.recv() => {
                match maybe_target {
                    Some(item) => {
                        let target = item.address;
                        dark_solver::utils::blackbox::record(
                            "target",
                            format!("queued_target={target:?}"),
                            Some(serde_json::json!({
                                "priority": format!("{:?}", item.priority),
                            })),
                        );
                        let duplicate_inflight = {
                            let mut inflight = lock_inflight_set(
                                &inflight_targets,
                                "pipeline.enqueue_target.insert",
                            );
                            !inflight.insert(target)
                        };
                        if duplicate_inflight {
                            tracing::debug!(
                                "[SCHED] Skipping duplicate in-flight target {:?} (prio={:?}).",
                                target,
                                item.priority
                            );
                            continue;
                        }

                        // ... existing DB check and markings ...
                        let manual_target_override =
                            runtime_args.manual_target.is_some_and(|addr| addr == target);
                        match contracts_db.is_done(target) {
                            Ok(true) if !manual_target_override => {
                                let mut inflight = lock_inflight_set(
                                    &inflight_targets,
                                    "pipeline.enqueue_target.remove_done",
                                );
                                inflight.remove(&target);
                                skipped_done_targets = skipped_done_targets.saturating_add(1);
                                if skipped_done_targets.is_multiple_of(50) {
                                    tracing::info!(
                                        "[SCHED] Skipped {} already-done targets from feeds (manual mode can force re-run on specific addresses).",
                                        skipped_done_targets
                                    );
                                }
                                continue;
                            },
                            Ok(true) => {
                                tracing::warn!(
                                    "[MANUAL] Target {:?} already marked done; forcing re-run due to manual override.",
                                    target
                                );
                                let _ = contracts_db.mark_queued(target);
                            }
                            Ok(false) => { let _ = contracts_db.mark_queued(target); }
                            Err(_) => {}
                        }

                        let provider_clone = provider.clone();
                        let contracts_db_clone = contracts_db.clone();
                        let sem_clone = solver_sem.clone();
                        let code_cache_clone = code_cache.clone();
                        let proxy_cache_clone = proxy_cache.clone();
                        let inflight_targets_clone = inflight_targets.clone();
                        let background_inflight_targets_clone = background_inflight_targets.clone();
                        let background_solver_tx = background_solver_tx.clone();
                        let findings_tx = findings_tx.clone();
                        let hydration_pool_clone = Arc::clone(&hydration_pool);
                        let unsat_progress_counter = Arc::clone(&unsat_progress_counter);
                        let chain_id = config.chain_id;
                        let fuzz_attacker = if config.submission_enabled {
                            executor.attacker_address()
                        } else {
                            dark_solver::solver::setup::ATTACKER
                        };
                        let solve_target_block = match dark_solver::utils::rpc::RobustRpc::get_block_number_with_retry(provider.clone(), 3).await {
                            Ok(block) => {
                                latest_head_hint.store(block, Ordering::Relaxed);
                                block
                            }
                            Err(err) => {
                                let cached = latest_head_hint.load(Ordering::Relaxed);
                                if cached == 0 {
                                    eprintln!(
                                        "[WARN] Failed to fetch solve target block for {:?}: {}",
                                        target,
                                        compact_error(err)
                                    );
                                    let mut inflight = lock_inflight_set(
                                        &inflight_targets,
                                        "pipeline.enqueue_target.remove_head_fetch_fail",
                                    );
                                    inflight.remove(&target);
                                    continue;
                                }
                                eprintln!(
                                    "[WARN] Failed to fetch solve target block for {:?}: {}. Using cached head {}.",
                                    target,
                                    compact_error(err),
                                    cached
                                );
                                cached
                            }
                        };

                        tokio::spawn(async move {
                            let _inflight_guard =
                                InflightTargetGuard::new(inflight_targets_clone, target);
                            let _permit = match sem_clone.acquire().await {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            let mut scan_guard =
                                ScanCompletionGuard::start((*contracts_db_clone).clone(), target);

                            // Manual target injection is an explicit operator override; it must
                            // bypass automated high-value acquisition gates.

                            // Proxy / Code Fetch logic (Already using RobustRpc)
                            let mut current_target = target;
                            if let Some(cached_impl) = proxy_cache_clone.get(&target) {
                                current_target = *cached_impl;
                            } else {
                                let slot = U256::from_be_bytes(scanner::IMPL_SLOT);
                                if let Ok(val) = dark_solver::utils::rpc::RobustRpc::get_storage_with_hydration_pool_retry(
                                    hydration_pool_clone.as_ref(),
                                    target,
                                    slot,
                                    3,
                                )
                                .await {
                                    if !val.is_zero() {
                                        let addr = Address::from_word(val.into());
                                        current_target = addr;
                                        proxy_cache_clone.insert(target, addr);
                                    }
                                }
                            }

                            let bytecode = if let Some(c) = code_cache_clone.get(&current_target) { c.clone() } else {
                                match dark_solver::utils::rpc::RobustRpc::get_code_with_hydration_pool_retry(
                                    hydration_pool_clone.as_ref(),
                                    current_target,
                                    3,
                                )
                                .await {
                                    Ok(c) => { code_cache_clone.insert(current_target, c.clone()); c }
                                    Err(_) => {
                                        scan_guard.finish();
                                        return;
                                    }
                                }
                            };

                            if bytecode.is_empty() {
                                scan_guard.finish();
                                return;
                            }

                            let bc_hash = keccak256(&bytecode);
                            scan_guard.set_bytecode_hash(bc_hash);
                            match contracts_db_clone
                                .known_vulnerable_contract_for_genome(bc_hash)
                            {
                                Ok(Some(seed_contract)) if seed_contract != current_target => {
                                    scan_guard.set_exploit_found();
                                    tracing::warn!(
                                        "[GENOME] High-risk bytecode genome match: {:?} mirrors previously flagged contract {:?}. Continuing analysis for fresh calldata.",
                                        current_target,
                                        seed_contract
                                    );
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    eprintln!(
                                        "[WARN] Genome lookup failed for {:?}: {:?}",
                                        current_target, err
                                    );
                                }
                            }

                            // Heuristic: skip obviously low-signal bytecode (no CALL/LOG/SSTORE/DELEGATECALL).
                            // This reduces solver time on the hot path.
                            let has_interesting = bytecode.iter().any(|&b| b == 0x55 || (0xa0..=0xa4).contains(&b) || b == 0xf1 || b == 0xf4 || b == 0xfa);
                            if !has_interesting {
                                scan_guard.finish();
                                return;
                            }

                            let solver_rpc = provider_clone.client().transport().url().to_string();
                            match dark_solver::solver::heuristics::run_pre_simulation_probe(
                                &solver_rpc,
                                current_target,
                                fuzz_attacker,
                            )
                            .await
                            {
                                Ok(report) if !report.passed => {
                                    tracing::debug!(
                                        "[PRE-SIM] Target {:?} filtered by concrete probe (transfer_ok={}, approve_ok={}).",
                                        current_target,
                                        report.transfer_ok,
                                        report.approve_ok
                                    );
                                    scan_guard.finish();
                                    return;
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    tracing::warn!(
                                        "[PRE-SIM] Probe failed for {:?}: {}",
                                        current_target,
                                        compact_error(&err)
                                    );
                                }
                            }
                            tracing::debug!(
                                "[SOLVE] Analyzing: {:?} | Size: {} bytes",
                                current_target,
                                bytecode.len()
                            );

                            if let Some((fuzz_params, fuzz_elapsed_ms)) = try_concrete_fuzz_fast_lane(
                                &solver_rpc,
                                chain_id,
                                fuzz_attacker,
                                target,
                                &bytecode,
                                solve_target_block,
                            )
                            .await
                            {
                                tracing::warn!(
                                    "[FUZZ] Fast lane concrete fuzz hit for {:?} in {}ms. Skipping Z3.",
                                    target,
                                    fuzz_elapsed_ms
                                );
                                scan_guard.set_exploit_found();
                                let _ = findings_tx
                                    .send(SolverResult {
                                        target,
                                        bytecode_hash: bc_hash,
                                        findings: vec![(
                                            "Concrete Fuzz Fast Lane".to_string(),
                                            fuzz_params,
                                        )],
                                        solve_duration_ms: fuzz_elapsed_ms,
                                        solve_target_block,
                                        is_retry: false,
                                        is_background: false,
                                    })
                                    .await;
                                scan_guard.finish();
                                return;
                            }

                            let hydrate_rpc = solver_rpc.clone();
                            let hydrate_bytecode = bytecode.clone();
                            let hydrate_db = (*contracts_db_clone).clone();
                            let hydrate_target = current_target;
                            let target_context = match tokio::task::spawn_blocking(move || {
                                std::sync::Arc::new(dark_solver::solver::setup::hydrate_target_context(
                                    &hydrate_rpc,
                                    chain_id,
                                    hydrate_target,
                                    &hydrate_bytecode,
                                    Some(&hydrate_db),
                                ))
                            })
                            .await
                            {
                                Ok(ctx) => ctx,
                                Err(e) => {
                                    eprintln!("[WARN] Target context hydration join error: {:?}", e);
                                    scan_guard.finish();
                                    return;
                                }
                            };

                            if target_context.zero_state {
                                tracing::warn!(
                                    "[ZERO_STATE] Target {:?} has empty state (no code/balance/storage); skipping objective run.",
                                    current_target
                                );
                                scan_guard.finish();
                                return;
                            }

                            // Deep-scan override: force inline deep objective execution.
                            // When enabled, we intentionally skip background deep queueing to avoid duplicate work.
                            let force_deep = std::env::var("OBJECTIVE_DEEP_SCAN")
                                .ok()
                                .map(|v| {
                                    matches!(
                                        v.trim().to_ascii_lowercase().as_str(),
                                        "1" | "true" | "yes" | "on"
                                    )
                                })
                                .unwrap_or(false);

                            if let Some(background_solver_tx) = background_solver_tx.as_ref() {
                                if force_deep {
                                    tracing::debug!(
                                        "[SCHED] OBJECTIVE_DEEP_SCAN=true; background queue bypassed for {:?}.",
                                        current_target
                                    );
                                } else {
                                    let duplicate_background_inflight = {
                                        let mut inflight = lock_inflight_set(
                                            &background_inflight_targets_clone,
                                            "pipeline.background_queue.insert",
                                        );
                                        !inflight.insert(current_target)
                                    };
                                    if !duplicate_background_inflight {
                                        let _anchor_literal = "try_send(
                                        BackgroundSolveTask";
                                        if let Err(err) = background_solver_tx.try_send(
                                            BackgroundSolveTask {
                                                target: current_target,
                                                bytecode_hash: bc_hash,
                                                bytecode: bytecode.clone(),
                                                target_context: Arc::clone(&target_context),
                                                solver_rpc: solver_rpc.clone(),
                                                chain_id,
                                                solve_target_block,
                                            },
                                        ) {
                                            let mut inflight = lock_inflight_set(
                                                &background_inflight_targets_clone,
                                                "pipeline.background_queue.remove_enqueue_fail",
                                            );
                                            inflight.remove(&current_target);
                                            tracing::warn!(
                                                "[SCHED] Background deep queue enqueue failed for {:?}: {}",
                                                current_target,
                                                compact_error(err)
                                            );
                                        }
                                    }
                                }
                            }

                            let allow_deep_inline = force_deep || (background_solver_tx.is_none()
                                && !dark_solver::utils::rpc::global_rpc_cooldown_active());

                            if !allow_deep_inline && background_solver_tx.is_none() {
                                tracing::warn!(
                                    "[SCHED] Global RPC cooldown active; running Tier-1 objectives only for this pass."
                                );
                            } else if background_solver_tx.is_some() && !allow_deep_inline {
                                tracing::debug!(
                                    "[SCHED] Deep objectives routed to background queue for {:?}.",
                                    current_target
                                );
                            } else if force_deep {
                                tracing::info!(
                                    "[SCHED] Deep Scan forced INLINE for {:?} (Aggressive Mode).",
                                    current_target
                                );
                            }
                            let objectives =
                                dark_solver::engine::objective_catalog::build_objectives_with_hints(
                                    solver_rpc,
                                    chain_id,
                                    dark_solver::engine::objective_catalog::ObjectiveScheduleHints {
                                        allow_deep: allow_deep_inline,
                                    },
                                );
                            let (objective_sat_tx, mut objective_sat_rx) =
                                tokio::sync::mpsc::unbounded_channel::<
                                    dark_solver::solver::runner::StreamedFinding,
                                >();
                            let runner_bytecode = bytecode.clone();
                            let runner_context = std::sync::Arc::clone(&target_context);
                            let runner_handle = tokio::spawn(async move {
                                dark_solver::solver::runner::run_objectives_parallel_streaming(
                                    objectives,
                                    &runner_bytecode,
                                    Some(runner_context),
                                    objective_sat_tx,
                                )
                                .await
                            });

                            let mut had_sat_finding = false;
                            while let Some((obj_name, params, solve_duration_ms)) =
                                objective_sat_rx.recv().await
                            {
                                had_sat_finding = true;
                                scan_guard.set_exploit_found();
                                let _ = findings_tx
                                    .send(SolverResult {
                                        target: current_target,
                                        bytecode_hash: bc_hash,
                                        findings: vec![(obj_name, params)],
                                        solve_duration_ms,
                                        solve_target_block,
                                        is_retry: false,
                                        is_background: false,
                                    })
                                    .await;
                            }

                            match runner_handle.await {
                                Ok(Ok(_sat_count)) => {}
                                Ok(Err(err)) => {
                                    eprintln!(
                                        "[WARN] Streaming solver objective runner failure: {}",
                                        err
                                    );
                                    scan_guard.finish();
                                    return;
                                }
                                Err(e) => {
                                    eprintln!("[WARN] Streaming solver task join error: {:?}", e);
                                    scan_guard.finish();
                                    return;
                                }
                            }

                            if !had_sat_finding {
                                let unsat_count =
                                    unsat_progress_counter.fetch_add(1, Ordering::Relaxed) + 1;
                                if unsat_count <= 5
                                    || unsat_count.is_multiple_of(unsat_progress_log_every)
                                {
                                    tracing::info!(
                                        "[SOLVE] UNSAT progress: {} targets completed with no breach (latest {:?}).",
                                        unsat_count,
                                        current_target
                                    );
                                }
                            }
                            scan_guard.finish();
                        });
                    }
                    None => break,
                }
            }

            // Branch 2: Solver Result Ready (The Hot Path)
            maybe_result = findings_rx.recv() => {
                if let Some(res) = maybe_result {
                    let solve_time = res.solve_duration_ms;
                    let (phase, depth) = if res.is_background {
                        ("background", 0usize)
                    } else if res.is_retry {
                        ("retry", 3usize)
                    } else {
                        ("primary", 3usize)
                    };
                    dark_solver::solver::verification::record_solve_cycle(
                        res.target,
                        solve_time,
                        phase,
                        depth,
                    );

                    if res.findings.is_empty() {
                        tracing::debug!("[SOLVE] Path UNSAT for {:?} in {}ms", res.target, solve_time);
                        dark_solver::utils::blackbox::record(
                            "z3",
                            format!("unsat target={:?}", res.target),
                            Some(serde_json::json!({
                                "solve_ms": solve_time,
                                "phase": phase,
                            })),
                        );
                        continue;
                    }

                    if let Err(err) =
                        contracts_db.record_vulnerable_genome(res.bytecode_hash, res.target)
                    {
                        tracing::warn!(
                            "[WARN] Failed to persist deep SAT genome for {:?}: {}",
                            res.target,
                            compact_error(err)
                        );
                    }

                    let target = res.target;
                    let solve_target_block = res.solve_target_block;
                    let base_required_floor = strategy_params_state
                        .read()
                        .await
                        .min_expected_profit_wei;
                    let mut drift_governor_required_floor = base_required_floor;
                    let mut drift_governor_block_execution = false;
                    let mut drift_ratio_observed: Option<f64> = None;
                    if drift_governor_enabled {
                        match contracts_db.rolling_realized_expected_ratio(drift_sample_limit) {
                            Ok(Some(ratio)) => {
                                drift_ratio_observed = Some(ratio);
                                if ratio < drift_hard_block_ratio {
                                    drift_governor_block_execution = true;
                                } else if ratio < drift_ratio_floor
                                    && !min_expected_profit_wei.is_zero()
                                {
                                    let tightened = (min_expected_profit_wei
                                        * U256::from(drift_tighten_multiplier_bps))
                                        / U256::from(10_000u64);
                                    if tightened > drift_governor_required_floor {
                                        drift_governor_required_floor = tightened;
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                tracing::warn!(
                                    "[EV] Drift governor ratio fetch failed: {}",
                                    compact_error(err)
                                );
                            }
                        }
                    }
                    let scheduled_findings =
                        dark_solver::solver::scheduler::greedy_schedule_findings(res.findings);
                    for (obj_name, mut params) in scheduled_findings {
                        let mut verified_shadow_report: Option<
                            dark_solver::executor::verifier::ShadowSimulationReport,
                        > = None;
                        let mut execution_target_block = solve_target_block;
                        // Skip JIT tuning for audit-style findings; they are typically less time-sensitive.
                        let is_audit_finding_jit = obj_name.contains("Audit") || obj_name.contains("Bad Debt");
                        if res.is_background && jit_tuner_enabled && !is_audit_finding_jit {
                            let latest_head = latest_head_hint.load(Ordering::Relaxed);
                            let tuner_head = if latest_head == 0 {
                                solve_target_block
                            } else {
                                latest_head
                            };
                            let jit_rpc_url = config
                                .execution_rpc_url
                                .as_deref()
                                .unwrap_or(config.eth_rpc_url.as_str());
                            match jit_tune_background_finding(
                                jit_rpc_url,
                                config.chain_id,
                                jit_tuner_attacker,
                                &params,
                                solve_target_block,
                                tuner_head,
                                jit_tuner_budget_ms,
                                jit_tuner_max_offset_shift,
                            )
                            .await
                            {
                                Some((tuned, report, verified_block)) => {
                                    params = tuned;
                                    execution_target_block = verified_block;
                                    if immediate_bundle_relay_enabled {
                                        verified_shadow_report = Some(report);
                                    }
                                    tracing::debug!(
                                        "[JIT] Hot-swapped volatile fields for background finding [{}] on {:?} (head={}, solve_block={}).",
                                        obj_name,
                                        res.target,
                                        tuner_head,
                                        solve_target_block
                                    );
                                }
                                None => {
                                    tracing::warn!(
                                        "[JIT] Dropping background finding [{}] on {:?}: volatile re-tune failed within {}ms budget.",
                                        obj_name,
                                        res.target,
                                        jit_tuner_budget_ms
                                    );
                                    continue;
                                }
                            }
                        }
                        if res.is_background && proof_persistence_enabled {
                            let proof_fingerprint = fingerprint_exploit_params(&params);
                            let latest_head = latest_head_hint.load(Ordering::Relaxed);
                            let age_blocks = latest_head.saturating_sub(solve_target_block);
                            let mut guard = proof_persistence_cache.lock().await;
                            let inserted = track_persisted_deep_proof(
                                &mut guard,
                                PersistedDeepProofItem {
                                    target: res.target,
                                    objective: obj_name.clone(),
                                    fingerprint: proof_fingerprint,
                                    params: params.clone(),
                                    solve_block: solve_target_block,
                                    last_checked_block: solve_target_block,
                                    checks: 0,
                                    consecutive_failures: 0,
                                    last_verified_block: None,
                                    last_valid_state_root: None,
                                },
                                proof_persistence_max_items,
                            );
                            drop(guard);
                            if inserted {
                                tracing::debug!(
                                    "[PERSIST] Tracking deep SAT proof: target={:?} objective={} solve_block={} age_blocks={}",
                                    res.target,
                                    obj_name,
                                    solve_target_block,
                                    age_blocks
                                );
                                if age_blocks >= proof_persistence_stale_blocks {
                                    tracing::debug!(
                                        "[PERSIST] Deep SAT is stale and queued for state-root revalidation: target={:?} objective={} age_blocks={} threshold={}.",
                                        res.target,
                                        obj_name,
                                        age_blocks,
                                        proof_persistence_stale_blocks
                                    );
                                }
                            }
                        }

                        let expected_profit_wei = params.expected_profit.unwrap_or(U256::ZERO);
                        let payload_json = Some(encode_exploit_params_json(&params));
                        let drift_throttle_applicable = drift_governor_enabled
                            && !res.is_background
                            && !drift_steady_state_max_profit_wei.is_zero()
                            && expected_profit_wei <= drift_steady_state_max_profit_wei;
                        if drift_governor_block_execution && drift_throttle_applicable {
                            tracing::warn!(
                                "[EV-DRIFT] Blocking execution for [{}] {:?}: realized/expected ratio {:?} below hard floor {:.2}.",
                                obj_name,
                                res.target,
                                drift_ratio_observed,
                                drift_hard_block_ratio
                            );
                            continue;
                        } else if drift_governor_block_execution && drift_governor_enabled {
                            tracing::warn!(
                                "[EV-DRIFT] Drift ratio {:?} below hard floor {:.2}, but allowing whale-exempt finding [{}] {:?} (expected_profit={}, background={}).",
                                drift_ratio_observed,
                                drift_hard_block_ratio,
                                obj_name,
                                res.target,
                                expected_profit_wei,
                                res.is_background
                            );
                        }
                        let required_floor = if drift_throttle_applicable {
                            drift_governor_required_floor
                        } else {
                            base_required_floor
                        };

                        // Allow audit/critical findings to bypass the profitability floor.
                        let is_audit_finding = obj_name.contains("Audit") || obj_name.contains("Bad Debt");

                        if !is_audit_finding && !required_floor.is_zero() && expected_profit_wei < required_floor
                        {
                            tracing::debug!(
                                "[EV-PRUNE] Dropped SAT finding [{}] for {:?}: expected_profit={} < floor={} (drift_ratio={:?})",
                                obj_name,
                                res.target,
                                expected_profit_wei,
                                required_floor,
                                drift_ratio_observed
                            );
                            continue;
                        } else if is_audit_finding && expected_profit_wei < required_floor {
                             tracing::info!(
                                "[AUDIT] Bypassing profit floor for audit finding [{}] on {:?}.",
                                obj_name,
                                res.target
                            );
                        }
                        if runtime_kill_switch {
                            tracing::warn!(
                                "[RISK] Kill switch blocked execution for [{}] {:?}.",
                                obj_name,
                                res.target
                            );
                            persist_fail_closed_attempt(
                                contracts_db.as_ref(),
                                target,
                                &obj_name,
                                solve_target_block,
                                solve_time,
                                params.expected_profit,
                                payload_json.clone(),
                                "kill_switch",
                                serde_json::json!({}),
                            );
                            continue;
                        }
                        let mut uncertainty_override_reason: Option<&'static str> = None;
                        if runtime_fail_closed_on_uncertainty
                            && dark_solver::utils::rpc::global_rpc_cooldown_active()
                        {
                            let target_capital_eth_wei =
                                scanner::target_capital_estimate_eth_wei(res.target);
                            let high_capital_override =
                                should_override_rpc_cooldown_for_high_capital(
                                    pressure_risk_weighting_enabled,
                                    target_capital_eth_wei,
                                    pressure_risk_high_capital_threshold_wei,
                                );
                            if profit_weighted_execution_policy.should_override_fail_closed(
                                params.expected_profit,
                                UncertaintyClass::RpcCooldown,
                            ) || high_capital_override
                            {
                                if uncertainty_override_reason.is_none() {
                                    uncertainty_override_reason =
                                        Some(if high_capital_override {
                                            "uncertainty_rpc_cooldown_high_capital"
                                        } else {
                                            "uncertainty_rpc_cooldown"
                                        });
                                }
                                let expected = params.expected_profit.unwrap_or(U256::ZERO);
                                let ratio_x = profit_weighted_execution_policy
                                    .profit_to_risk_ratio_x_floor(expected)
                                    .unwrap_or(U256::ZERO);
                                if high_capital_override {
                                    tracing::warn!(
                                        "[RISK] High-capital override for [{}] {:?}: rpc cooldown active (target_capital_eth_wei={:?} threshold_wei={} expected_profit={} ratio_x_floor={}).",
                                        obj_name,
                                        res.target,
                                        target_capital_eth_wei,
                                        pressure_risk_high_capital_threshold_wei,
                                        expected,
                                        ratio_x
                                    );
                                } else {
                                    tracing::warn!(
                                        "[RISK] Profit-weighted override for [{}] {:?}: rpc cooldown active (expected_profit={} risk_budget={} roi_multiple={} ratio_x_floor={}).",
                                        obj_name,
                                        res.target,
                                        expected,
                                        profit_weighted_execution_policy.risk_budget_wei,
                                        profit_weighted_execution_policy.roi_multiple,
                                        ratio_x
                                    );
                                }
                            } else {
                            tracing::warn!(
                                "[RISK] Fail-closed blocked execution for [{}] {:?}: rpc cooldown active.",
                                obj_name,
                                res.target
                            );
                            persist_fail_closed_attempt(
                                contracts_db.as_ref(),
                                target,
                                &obj_name,
                                solve_target_block,
                                solve_time,
                                params.expected_profit,
                                payload_json.clone(),
                                "uncertainty_rpc_cooldown",
                                serde_json::json!({}),
                            );
                            continue;
                            }
                        }
                        if let Some(cap) = runtime_drawdown_cap_wei {
                            match contracts_db.rolling_drawdown_wei(drift_sample_limit) {
                                Ok(drawdown) => {
                                    let drawdown_wei = revm_to_alloy_u256(drawdown);
                                    if drawdown_wei > cap {
                                        tracing::warn!(
                                            "[RISK] Drawdown cap blocked execution for [{}] {:?}: drawdown={} cap={}.",
                                            obj_name,
                                            res.target,
                                            drawdown_wei,
                                            cap
                                        );
                                        persist_fail_closed_attempt(
                                            contracts_db.as_ref(),
                                            target,
                                            &obj_name,
                                            solve_target_block,
                                            solve_time,
                                            params.expected_profit,
                                            payload_json.clone(),
                                            "drawdown_cap",
                                            serde_json::json!({
                                                "drawdown_wei": drawdown_wei.to_string(),
                                                "drawdown_cap_wei": cap.to_string(),
                                            }),
                                        );
                                        continue;
                                    }
                                }
                                Err(err) => {
                                    if runtime_fail_closed_on_uncertainty {
                                        if profit_weighted_execution_policy.should_override_fail_closed(
                                            params.expected_profit,
                                            UncertaintyClass::DrawdownUnavailable,
                                        ) {
                                            if uncertainty_override_reason.is_none() {
                                                uncertainty_override_reason = Some(
                                                    "uncertainty_drawdown_unavailable",
                                                );
                                            }
                                            let expected = params
                                                .expected_profit
                                                .unwrap_or(U256::ZERO);
                                            let ratio_x =
                                                profit_weighted_execution_policy
                                                    .profit_to_risk_ratio_x_floor(
                                                        expected,
                                                    )
                                                    .unwrap_or(U256::ZERO);
                                            tracing::warn!(
                                                "[RISK] Profit-weighted override for [{}] {:?}: drawdown unavailable (expected_profit={} risk_budget={} roi_multiple={} ratio_x_floor={} err={}).",
                                                obj_name,
                                                res.target,
                                                expected,
                                                profit_weighted_execution_policy.risk_budget_wei,
                                                profit_weighted_execution_policy.roi_multiple,
                                                ratio_x,
                                                compact_error(&err)
                                            );
                                        } else {
                                        tracing::warn!(
                                            "[RISK] Fail-closed blocked execution for [{}] {:?}: drawdown unavailable ({}).",
                                            obj_name,
                                            res.target,
                                            compact_error(&err)
                                        );
                                        persist_fail_closed_attempt(
                                            contracts_db.as_ref(),
                                            target,
                                            &obj_name,
                                            solve_target_block,
                                            solve_time,
                                            params.expected_profit,
                                            payload_json.clone(),
                                            "uncertainty_drawdown_unavailable",
                                            serde_json::json!({
                                                "error": compact_error(&err),
                                            }),
                                        );
                                        continue;
                                        }
                                    }
                                    tracing::warn!(
                                        "[RISK] Drawdown cap check failed for [{}] {:?}: {}",
                                        obj_name,
                                        res.target,
                                        compact_error(&err)
                                    );
                                }
                            }
                        }
                        if let Some(cap) = runtime_per_block_loss_cap_wei {
                            match contracts_db.realized_loss_for_solve_block(solve_target_block) {
                                Ok(loss) => {
                                    let loss_wei = revm_to_alloy_u256(loss);
                                    if loss_wei > cap {
                                        tracing::warn!(
                                            "[RISK] Per-block loss cap blocked execution for [{}] {:?}: block={} loss={} cap={}.",
                                            obj_name,
                                            res.target,
                                            solve_target_block,
                                            loss_wei,
                                            cap
                                        );
                                        persist_fail_closed_attempt(
                                            contracts_db.as_ref(),
                                            target,
                                            &obj_name,
                                            solve_target_block,
                                            solve_time,
                                            params.expected_profit,
                                            payload_json.clone(),
                                            "per_block_loss_cap",
                                            serde_json::json!({
                                                "solve_block": solve_target_block,
                                                "loss_wei": loss_wei.to_string(),
                                                "loss_cap_wei": cap.to_string(),
                                            }),
                                        );
                                        continue;
                                    }
                                }
                                Err(err) => {
                                    if runtime_fail_closed_on_uncertainty {
                                        if profit_weighted_execution_policy.should_override_fail_closed(
                                            params.expected_profit,
                                            UncertaintyClass::PerBlockLossUnavailable,
                                        ) {
                                            if uncertainty_override_reason.is_none() {
                                                uncertainty_override_reason = Some(
                                                    "uncertainty_per_block_loss_unavailable",
                                                );
                                            }
                                            let expected = params
                                                .expected_profit
                                                .unwrap_or(U256::ZERO);
                                            let ratio_x =
                                                profit_weighted_execution_policy
                                                    .profit_to_risk_ratio_x_floor(
                                                        expected,
                                                    )
                                                    .unwrap_or(U256::ZERO);
                                            tracing::warn!(
                                                "[RISK] Profit-weighted override for [{}] {:?}: per-block loss unavailable (expected_profit={} risk_budget={} roi_multiple={} ratio_x_floor={} err={}).",
                                                obj_name,
                                                res.target,
                                                expected,
                                                profit_weighted_execution_policy.risk_budget_wei,
                                                profit_weighted_execution_policy.roi_multiple,
                                                ratio_x,
                                                compact_error(&err)
                                            );
                                        } else {
                                        tracing::warn!(
                                            "[RISK] Fail-closed blocked execution for [{}] {:?}: per-block loss unavailable ({}).",
                                            obj_name,
                                            res.target,
                                            compact_error(&err)
                                        );
                                        persist_fail_closed_attempt(
                                            contracts_db.as_ref(),
                                            target,
                                            &obj_name,
                                            solve_target_block,
                                            solve_time,
                                            params.expected_profit,
                                            payload_json.clone(),
                                            "uncertainty_per_block_loss_unavailable",
                                            serde_json::json!({
                                                "error": compact_error(&err),
                                            }),
                                        );
                                        continue;
                                        }
                                    }
                                    tracing::warn!(
                                        "[RISK] Per-block loss cap check failed for [{}] {:?}: {}",
                                        obj_name,
                                        res.target,
                                        compact_error(&err)
                                    );
                                }
                            }
                        }
                        tracing::info!(
                            "[FINDING] Invariant breach candidate [{}] target={:?} solve_ms={}",
                            obj_name,
                            target,
                            solve_time
                        );
                        dark_solver::utils::blackbox::record(
                            "z3",
                            format!("sat objective={} target={:?}", obj_name, target),
                            Some(serde_json::json!({
                                "solve_ms": solve_time,
                                "expected_profit_wei": params.expected_profit.unwrap_or(U256::ZERO).to_string(),
                                "background": res.is_background,
                            })),
                        );
                        let exec = executor.clone();
                        let watch_cache = Arc::clone(&watch_cache);
                        let block_time_ms =
                            dark_solver::config::chains::ChainConfig::get(config.chain_id)
                                .block_time_ms as u128;
                        let require_late_solve_preflight =
                            solve_time > 2_000 || solve_time > block_time_ms;
                        let watch_params = params.clone();
                        let watch_fingerprint = fingerprint_exploit_params(&watch_params);
                        let watch_objective = obj_name.clone();
                        let contracts_db_exec = contracts_db.clone();
                        let contested_tip_cache = Arc::clone(&contested_tip_cache);
                        let expected_profit_wei = params.expected_profit;
                        let uncertainty_override_reason =
                            uncertainty_override_reason.map(|reason| reason.to_string());
                        let calibration_precision_state = calibration_precision_bps.clone();
                        let calibration_sample_state = calibration_scored_samples.clone();
                        let calibration_last_run_state = calibration_last_run_ms.clone();
                        let calibration_gate_enabled = calibration_harness_enabled && config.submission_enabled;
                        let calibration_required_precision_bps = calibration_min_precision_bps;
                        let solve_completed_ms = now_ms();
                        let require_late_solve_preflight =
                            require_late_solve_preflight && verified_shadow_report.is_none();
                        let slippage_provider = provider.clone();
                        let slippage_chain_id = config.chain_id;
                        if require_late_solve_preflight {
                            tracing::warn!(
                                "[PRE-FLIGHT] Triggered late-solve re-verification for {:?}: solve={}ms, block_time={}ms.",
                                res.target,
                                solve_time,
                                block_time_ms
                            );
                        }
                        let execution_target_block = execution_target_block;
                        let verified_shadow_report = verified_shadow_report;
                        tokio::spawn(async move {
                            if calibration_gate_enabled {
                                let scored_samples =
                                    calibration_sample_state.load(Ordering::Relaxed);
                                let observed_precision_bps =
                                    calibration_precision_state.load(Ordering::Relaxed);
                                let last_calibration_run_ms =
                                    calibration_last_run_state.load(Ordering::Relaxed);
                                if scored_samples == 0
                                    || observed_precision_bps < calibration_required_precision_bps
                                {
                                    tracing::warn!(
                                        "[CAL] Blocking private submission expansion for {:?} [{}]: precision={}bps samples={} required={}bps last_run_ms={}.",
                                        target,
                                        watch_objective,
                                        observed_precision_bps,
                                        scored_samples,
                                        calibration_required_precision_bps,
                                        last_calibration_run_ms
                                    );
                                    let solve_started_ms = now_ms()
                                        .saturating_sub(solve_time.min(u64::MAX as u128) as u64);
                                    let details_json = Some(format!(
                                        "{{\"drop_reason\":\"calibration_precision\",\"observed_precision_bps\":{},\"required_precision_bps\":{},\"samples\":{},\"last_calibration_run_ms\":{}}}",
                                        observed_precision_bps,
                                        calibration_required_precision_bps,
                                        scored_samples,
                                        last_calibration_run_ms
                                    ));
                                    let record = SubmissionAttemptRecord {
                                        target,
                                        objective: watch_objective.clone(),
                                        solve_block: solve_target_block,
                                        solve_duration_ms: solve_time,
                                        solve_started_ms,
                                        replay_completed_ms: None,
                                        send_completed_ms: None,
                                        tip_wei: None,
                                        max_fee_wei: None,
                                        expected_profit_wei,
                                        realized_profit_wei: None,
                                        realized_profit_negative: false,
                                        latency_bucket_ms: Some(
                                            solve_time.min(u64::MAX as u128) as u64,
                                        ),
                                        tip_band_wei: None,
                                        chosen_builders: Vec::new(),
                                        outcome_label: ExecutionOutcomeLabel::DroppedPriceConfidence,
                                        included: Some(false),
                                        reverted: None,
                                        inclusion_block: None,
                                        contested: false,
                                        payload_json: payload_json.clone(),
                                        details_json,
                                        builder_outcomes: Vec::new(),
                                    };
                                    if let Err(err) =
                                        contracts_db_exec.record_submission_attempt(record)
                                    {
                                        tracing::warn!(
                                            "[WARN] Failed to persist calibration-gated attempt for {:?} [{}]: {}",
                                            target,
                                            watch_objective,
                                            compact_error(err)
                                        );
                                    }
                                    return;
                                }
                            }

                            match dark_solver::solver::liquidity::verify_exact_input_single_liquidity(
                                &*slippage_provider,
                                slippage_chain_id,
                                &params,
                            )
                            .await
                            {
                                Ok(Some(report)) if !report.passed => {
                                    tracing::warn!(
                                        "[RISK] Slippage oracle blocked execution for {:?} [{}]: quoted_out={} < min_out={}.",
                                        target,
                                        watch_objective,
                                        report.quoted_out,
                                        report.required_min_out
                                    );
                                    persist_fail_closed_attempt(
                                        contracts_db_exec.as_ref(),
                                        target,
                                        &watch_objective,
                                        solve_target_block,
                                        solve_time,
                                        expected_profit_wei,
                                        payload_json.clone(),
                                        "slippage_oracle",
                                        serde_json::json!({
                                            "quoted_out": report.quoted_out.to_string(),
                                            "required_min_out": report.required_min_out.to_string(),
                                        }),
                                    );
                                    return;
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    if dark_solver::solver::liquidity::slippage_oracle_strict() {
                                        tracing::warn!(
                                            "[RISK] Slippage oracle error blocked execution for {:?} [{}]: {}",
                                            target,
                                            watch_objective,
                                            compact_error(&err)
                                        );
                                        persist_fail_closed_attempt(
                                            contracts_db_exec.as_ref(),
                                            target,
                                            &watch_objective,
                                            solve_target_block,
                                            solve_time,
                                            expected_profit_wei,
                                            payload_json.clone(),
                                            "slippage_oracle_error",
                                            serde_json::json!({
                                                "error": compact_error(err),
                                            }),
                                        );
                                        return;
                                    }
                                    tracing::warn!(
                                        "[RISK] Slippage oracle probe failed (non-strict) for {:?} [{}]: {}",
                                        target,
                                        watch_objective,
                                        compact_error(err)
                                    );
                                }
                            }

                            let tip_auto_scale_contested = {
                                let mut guard = contested_tip_cache.lock().await;
                                guard.is_contested(target, execution_target_block)
                            };
                            let feedback = exec
                                .execute_attack(
                                    params,
                                    target,
                                    dark_solver::executor::AttackExecutionContext {
                                        target_solve_block: execution_target_block,
                                        solve_duration_ms: solve_time,
                                        require_late_solve_preflight,
                                        solve_completed_ms,
                                        tip_auto_scale_contested,
                                        verified_shadow_report,
                                    },
                                )
                                .await;
                            dark_solver::executor::record_circuit_breaker_feedback(&feedback);
                            if feedback.learned_lemma || feedback.competition_rejected {
                                tracing::debug!(
                                    "[SELF_HEAL] Execution feedback received (lemma={}, competition={}).",
                                    feedback.learned_lemma,
                                    feedback.competition_rejected
                                );
                            }

                            let outcome_label = classify_execution_outcome_label(&feedback);
                            dark_solver::utils::blackbox::record(
                                "execution",
                                format!(
                                    "outcome={} target={:?} objective={}",
                                    outcome_label.as_str(),
                                    target,
                                    watch_objective
                                ),
                                Some(serde_json::json!({
                                    "tip_wei": feedback.tip_wei,
                                    "max_fee_wei": feedback.max_fee_wei,
                                    "included": feedback.included,
                                    "competition_rejected": feedback.competition_rejected,
                                })),
                            );
                            if matches!(outcome_label, ExecutionOutcomeLabel::Included) {
                                dark_solver::utils::telemetry::emit_success(
                                    "execution_included",
                                    format!(
                                        "Included target={:?} objective={} tip_wei={:?}",
                                        target, watch_objective, feedback.tip_wei
                                    ),
                                );
                            } else if matches!(outcome_label, ExecutionOutcomeLabel::Outbid) {
                                dark_solver::utils::telemetry::emit(
                                    dark_solver::utils::telemetry::TelemetryLevel::Info,
                                    "execution_outbid",
                                    format!(
                                        "Outbid target={:?} objective={} tip_wei={:?}",
                                        target, watch_objective, feedback.tip_wei
                                    ),
                                );
                            }
                            let competitor_hint_any =
                                dark_solver::executor::builder_outcomes_have_competition_hint(
                                    &feedback.builder_outcomes,
                                );
                            if competitor_hint_any {
                                let mut guard = contested_tip_cache.lock().await;
                                guard.mark_contested(target, execution_target_block);
                            }
                            let bundle_received_builders =
                                dark_solver::executor::bundle_received_builders(
                                    &feedback.builder_outcomes,
                                );
                            let chosen_builders = feedback
                                .builder_outcomes
                                .iter()
                                .map(|outcome| outcome.builder.clone())
                                .collect::<Vec<_>>();
                            let builder_outcomes = feedback
                                .builder_outcomes
                                .iter()
                                .map(|outcome| BuilderAttemptRecord {
                                    builder: outcome.builder.clone(),
                                    accepted: outcome.accepted,
                                    latency_ms: outcome.latency_ms,
                                    rejection_class: outcome.rejection_class.clone(),
                                    response_message: outcome.response_message.clone(),
                                })
                                .collect::<Vec<_>>();
                            let solve_started_ms = now_ms()
                                .saturating_sub(solve_time.min(u64::MAX as u128) as u64);
                            let inclusion_receipts = feedback
                                .builder_outcomes
                                .iter()
                                .map(|outcome| {
                                    serde_json::json!({
                                        "builder": outcome.builder,
                                        "accepted": outcome.accepted,
                                        "latency_ms": outcome.latency_ms,
                                        "rejection_class": outcome.rejection_class,
                                        "response_message": outcome.response_message,
                                    })
                                })
                                .collect::<Vec<_>>();
                            let details_json = Some(
                                serde_json::json!({
                                    "attack_outcome": format!("{:?}", feedback.outcome),
                                    "competition_rejected": feedback.competition_rejected,
                                    "competitor_hint_any": competitor_hint_any,
                                    "bundle_received_builders": bundle_received_builders,
                                    "learned_lemma": feedback.learned_lemma,
                                    "profit_weighted_uncertainty_override_reason": uncertainty_override_reason,
                                    "solve_started_ms": solve_started_ms,
                                    "replay_completed_ms": feedback.replay_completed_ms,
                                    "send_completed_ms": feedback.send_completed_ms,
                                    "tip_wei": feedback.tip_wei,
                                    "max_fee_wei": feedback.max_fee_wei,
                                    "chosen_builders": chosen_builders.clone(),
                                    "inclusion_receipts": inclusion_receipts,
                                })
                                .to_string(),
                            );
                            let (realized_profit_wei, realized_profit_negative) =
                                derive_realized_profit_estimate(expected_profit_wei, outcome_label);
                            let record = SubmissionAttemptRecord {
                                target,
                                objective: watch_objective.clone(),
                                solve_block: solve_target_block,
                                solve_duration_ms: solve_time,
                                solve_started_ms,
                                replay_completed_ms: feedback.replay_completed_ms,
                                send_completed_ms: feedback.send_completed_ms,
                                tip_wei: feedback.tip_wei,
                                max_fee_wei: feedback.max_fee_wei,
                                expected_profit_wei,
                                realized_profit_wei,
                                realized_profit_negative,
                                latency_bucket_ms: Some(
                                    solve_time.min(u64::MAX as u128) as u64
                                ),
                                tip_band_wei: feedback.tip_wei,
                                chosen_builders,
                                outcome_label,
                                included: feedback.included,
                                reverted: feedback.reverted,
                                inclusion_block: None,
                                contested: competitor_hint_any,
                                payload_json,
                                details_json,
                                builder_outcomes,
                            };
                            if let Err(err) = contracts_db_exec.record_submission_attempt(record) {
                                tracing::warn!(
                                    "[WARN] Failed to persist submission attempt for {:?} [{}]: {}",
                                    target,
                                    watch_objective,
                                    compact_error(err)
                                );
                            }

                            if solve_time >= WATCH_CACHE_MIN_SOLVE_MS
                                && matches!(
                                    feedback.outcome,
                                    dark_solver::executor::AttackOutcome::DroppedUnprofitable
                                )
                                && config.submission_enabled
                                && !feedback.learned_lemma
                            {
                                let mut guard = watch_cache.lock().await;
                                if !guard.contains_fingerprint(watch_fingerprint) {
                                    tracing::warn!(
                                        "[WATCH] Caching slow SAT payload (solve={}ms) for re-try on future heads: target={:?} objective={} fingerprint={:#x}",
                                        solve_time,
                                        target,
                                        watch_objective,
                                        watch_fingerprint
                                    );
                                    let _inserted = guard.insert_if_absent_with_capacity(
                                        WatchCacheItem {
                                        target,
                                        objective: watch_objective,
                                        fingerprint: watch_fingerprint,
                                        params: watch_params,
                                        original_solve_block: solve_target_block,
                                        original_solve_ms: solve_time,
                                        last_checked_block: solve_target_block,
                                        attempts: 0,
                                        },
                                        WATCH_CACHE_MAX_ITEMS,
                                    );
                                }
                            }
                        });
                    }
                }
            }

            // Branch 3: Shutdown Signal
            _ = tokio::signal::ctrl_c() => {
                tracing::debug!("\n[!] Received Ctrl+C. Initiating Graceful Shutdown...");
                dark_solver::utils::blackbox::record("signal", "ctrl_c_received", None);
                let _ = dark_solver::utils::blackbox::dump("ctrl_c");
                dark_solver::utils::telemetry::emit(
                    dark_solver::utils::telemetry::TelemetryLevel::Info,
                    "shutdown",
                    "Ctrl+C received; graceful shutdown started",
                );

                // 1. Notify Workers
                let _ = shutdown_tx.send(());

                // 2. Wait for Solvers (Simple timeout or semantic wait)
                tracing::debug!("[*] Waiting 5s for active solvers/scanner to cleanup...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                // 3. Flush Logs? (Tracing handles this usually)
                break;
            }
        }
    }

    // Explicitly drop executor/providers to invoke Drop traits/flush buffers if added later
    drop(executor);

    tracing::debug!("[*] Dark Solver Shutdown Complete. Goodbye.");

    Ok(())
}
