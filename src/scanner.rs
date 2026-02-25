use crate::storage::contracts_db::ContractsDb;
use alloy::consensus::Transaction; // Trait for .to() and .input()
use alloy::network::{ReceiptResponse, TransactionResponse};
use alloy::primitives::{address, keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::SolCall;
use anyhow::Result;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;

use crate::target_queue::{TargetPriority, TargetQueueSender};

// EIP-1967 Implementation Slot: keccak-256 hash of "eip1967.proxy.implementation" - 1
pub const IMPL_SLOT: [u8; 32] = [
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x2d, 0x02, 0x2d, 0x73,
    0x29, 0x30, 0xf0, 0x87, 0x3e, 0x30, 0x73, 0x31, 0x7a, 0x6e, 0x1d, 0x10, 0x90, 0xd0, 0x1f, 0x0c,
];

/// Approx. $100 in ETH at 3000 USD/ETH.
const DEFAULT_DUST_MIN_LIQUIDITY_WEI: u128 = 33_333_333_333_333_333;
const DEFAULT_HYDRATION_BASE_TIMEOUT_MS: u64 = 3_500;
const DEFAULT_CHAIN_ID_TIMEOUT_MS: u64 = 1_200;
const DEFAULT_HEAD_FETCH_TIMEOUT_MS: u64 = 1_500;
const DEFAULT_HASH_MODE_BLOCK_FETCH_TIMEOUT_MS: u64 = 1_200;
const DEFAULT_HASH_MODE_TX_FETCH_TIMEOUT_MS: u64 = 800;
const DEFAULT_HASH_MODE_RECEIPT_FETCH_TIMEOUT_MS: u64 = 800;
const DEFAULT_HASH_MODE_BLOCK_BUDGET_MS: u64 = 4_000;
const DEFAULT_HASH_MODE_RECEIPT_FALLBACK_BUDGET_PER_BLOCK: usize = 24;
const DEFAULT_BACKFILL_BLOCK_RECEIPTS_TIMEOUT_MS: u64 = 1_500;
const DEFAULT_LOG_DEPLOY_RECEIPT_TIMEOUT_MS: u64 = 900;
const DEFAULT_HIGH_VALUE_TVL_USD: u128 = 1_000_000;
const DEFAULT_WHALE_HUNTING_MIN_TVL_USD: u128 = 50_000;
const DEFAULT_CAPITAL_PROFILER_USD: u128 = 10_000;
const DEFAULT_ETH_USD: u128 = 3_000;
const ONE_ETH_WEI: u128 = 1_000_000_000_000_000_000;
const HIGH_VALUE_MULTICALL_TIMEOUT_MS: u64 = 350;
const DEFAULT_CAPITAL_PROFILER_MAX_ADDRS_PER_BLOCK: usize = 48;
const CAPITAL_PROFILER_MAX_MULTICALL_CALLS: usize = 180;
const DEFAULT_CAPITAL_PROFILER_MAX_CHUNK_CALLDATA_BYTES: usize = 24_000;
const DEFAULT_CAPITAL_PROFILER_BLOCK_BUDGET_MS: u64 = 500;
const DEFAULT_CAPITAL_PROFILER_CARRYOVER_MAX_ADDRS: usize = 512;
const DEFAULT_FALLBACK_TX_BY_HASH_SEMAPHORE_LIMIT: usize = 8;
const DEFAULT_FALLBACK_RECEIPT_SEMAPHORE_LIMIT: usize = 8;
const DEFAULT_LINKAGE_SEMAPHORE_LIMIT: usize = 2;
const DEFAULT_DUST_SWEEPER_MAX_PER_BLOCK: usize = 12;
const DEFAULT_DUST_CANDIDATE_SET_MAX_PER_BLOCK: usize = 128;
const DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN: usize = 4;
const DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS: u64 = 300_000;
const DEFAULT_HIGH_VALUE_PROBES_PER_BLOCK: usize = 8;
const DEFAULT_HIGH_VALUE_DEPLOYMENT_PROBES_PER_BLOCK: usize = 2;
static FULL_BLOCK_HYDRATION_ENABLED: AtomicBool = AtomicBool::new(true);
static FULL_BLOCK_HYDRATION_FAILURE_STREAK: AtomicU32 = AtomicU32::new(0);
static LAST_HYDRATED_BLOCK_TX_COUNT: AtomicU32 = AtomicU32::new(120);
static FULL_BLOCK_HYDRATION_DISABLED_UNTIL_MS: AtomicU64 = AtomicU64::new(0);
static LAST_SCANNER_NOW_MS: AtomicU64 = AtomicU64::new(1);

const DEFAULT_PRIORITY_SEQUENCE_POLL_MS: u64 = 400;
const DEFAULT_PRIORITY_SEQUENCE_MAX_TXS_PER_POLL: usize = 180;
const DEFAULT_PRIORITY_SEQUENCE_MAX_ADDRS_PER_TX: usize = 8;
const DEFAULT_PRIORITY_SEQUENCE_ADDRESS_COOLDOWN_MS: u64 = 15_000;
const DEFAULT_LOG_LIGHT_ADDRESS_COOLDOWN_MS: u64 = 10_000;
const DEFAULT_LOG_LIGHT_MAX_ADDRS_PER_MIN: usize = 2_000;
const DEFAULT_LOG_LIGHT_HIGH_VALUE_PROBES_PER_MIN: usize = 120;
const DEFAULT_LOG_LIGHT_MAX_ADDRS_PER_MIN_TVL_GATED: usize = 400;
const DEFAULT_LOG_LIGHT_HIGH_VALUE_PROBES_PER_MIN_TVL_GATED: usize = 120;
const DEFAULT_FULL_BLOCK_INGEST_PARALLELISM: usize = 16;
const DEFAULT_FULL_BLOCK_DEFERRED_HIGH_VALUE_PROBES_PER_BLOCK: usize = 4;
const DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_TIMEOUT_MS: u64 = 750;
const DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_MAX_ADDRS_PER_BLOCK: usize = 48;
const DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_MAX_LOGS_PER_BLOCK: usize = 750;
const DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_MAX_TOPICS_PER_LOG: usize = 3;
const DEFAULT_SEQUENCER_WS_INGESTION_MAX_TXS_PER_SEC: usize = 250;
const DEFAULT_SEQUENCER_WS_INGESTION_MAX_ADDRS_PER_TX: usize = 8;
const DEFAULT_SEQUENCER_WS_INGESTION_ADDRESS_COOLDOWN_MS: u64 = 7_500;
const DEFAULT_SEQUENCER_WS_INGESTION_ALLOW_HASH_FALLBACK: bool = false;
const DEFAULT_SEQUENCER_WS_HIGH_VALUE_PROBES_PER_SEC: usize = 20;
const DEFAULT_SEQUENCER_WS_HIGH_VALUE_PROBE_COOLDOWN_MS: u64 = 30_000;
const DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_TRACKED: usize = 25_000;
const DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_TTL_MS: u64 = 120_000;
const DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_PROBES_PER_HEAD: usize = 48;
const DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_CODE_TIMEOUT_MS: u64 = 150;
const DEFAULT_BLOCK_WORKER_CONCURRENCY: usize = 50;
const DEFAULT_LINKAGE_DISCOVERY_HIGH_VALUE_BUDGET: usize = 1;
const DEFAULT_WS_GAP_REPLAY_MAX_BLOCKS_PER_ITERATION: u64 = 64;
const DEFAULT_WS_GAP_REPLAY_YIELD_MS: u64 = 10;
const DEFAULT_UNKNOWN_OPSTACK_WRITE_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_PUBLIC_WS_RACE_CHANNEL_CAPACITY: usize = 4_096;
const DEFAULT_WS_CONNECT_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_WS_SUBSCRIBE_TIMEOUT_MS: u64 = 10_000;

// EIP-2470 Singleton Factory (Create2 deployer). This is a common "pending CREATE2" surface.
const EIP2470_SINGLETON_FACTORY: Address = address!("4e59b44847b379578588920ca78fbf26c0b4956c");

const HIGH_VALUE_CACHE_MAX_ENTRIES: usize = 200_000;
const HIGH_VALUE_CACHE_TTL_MS: u64 = 10 * 60 * 1_000;
const CAPITAL_ESTIMATE_CACHE_MAX_ENTRIES: usize = 200_000;
const CAPITAL_ESTIMATE_CACHE_TTL_MS: u64 = 30 * 60 * 1_000;
const STRUCTURAL_HUBRIS_SURFACE_CACHE_MAX_ENTRIES: usize = 100_000;

alloy::sol! {
    struct Multicall3Call {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Multicall3Result {
        bool success;
        bytes returnData;
    }

    function aggregate3(Multicall3Call[] calldata calls)
        external
        payable
        returns (Multicall3Result[] memory returnData);
}

struct LogThrottleState {
    last_log: Instant,
    suppressed: u64,
}

struct HeadRaceEvent {
    number: u64,
    hash: B256,
    source: String,
}

struct HighValueUnknownAdmissionState {
    window_start_ms: u64,
    admitted_in_window: usize,
    last_admit_ms_by_addr: HashMap<Address, u64>,
}

#[derive(Clone, Copy, Debug)]
enum PredictedDeploymentKind {
    Create,
    Create2SingletonFactory,
}

#[derive(Clone, Copy, Debug)]
struct PredictedDeployment {
    kind: PredictedDeploymentKind,
    first_seen_ms: u64,
    last_seen_ms: u64,
    from: Address,
    nonce: u64,
}

#[derive(Clone)]
struct UnknownOpstackDecodeWrite {
    db: ContractsDb,
    block_number: u64,
    tx_hash: Option<B256>,
    stage: String,
    error_class: String,
    raw_error: String,
}

fn warn_scan_throttled(message: String) {
    static STATE: OnceLock<Mutex<LogThrottleState>> = OnceLock::new();
    let state = STATE.get_or_init(|| {
        let now = Instant::now();
        let initial = now.checked_sub(Duration::from_secs(30)).unwrap_or(now);
        Mutex::new(LogThrottleState {
            last_log: initial,
            suppressed: 0,
        })
    });

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    if now.duration_since(guard.last_log) >= Duration::from_secs(10) {
        if guard.suppressed > 0 {
            tracing::warn!(
                "{} ({} similar scanner warning(s) suppressed)",
                message,
                guard.suppressed
            );
            guard.suppressed = 0;
        } else {
            tracing::warn!("{}", message);
        }
        guard.last_log = now;
    } else {
        guard.suppressed = guard.suppressed.saturating_add(1);
    }
}

fn now_ms() -> u64 {
    let sample = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_scanner_now_ms(sample)
}

fn normalize_scanner_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_SCANNER_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_SCANNER_NOW_MS.compare_exchange_weak(
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

fn high_value_unknown_admission_state() -> &'static Mutex<HighValueUnknownAdmissionState> {
    static STATE: OnceLock<Mutex<HighValueUnknownAdmissionState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(HighValueUnknownAdmissionState {
            window_start_ms: now_ms(),
            admitted_in_window: 0,
            last_admit_ms_by_addr: HashMap::new(),
        })
    })
}

fn allow_high_value_unknown_admission(address: Address) -> bool {
    let budget = load_high_value_unknown_admit_budget_per_min();
    let cooldown_ms = load_high_value_unknown_admit_cooldown_ms();
    let now = now_ms();
    let mut state = match high_value_unknown_admission_state().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };

    if now.saturating_sub(state.window_start_ms) >= 60_000 {
        state.window_start_ms = now;
        state.admitted_in_window = 0;
    }
    if state.admitted_in_window >= budget {
        return false;
    }
    if state
        .last_admit_ms_by_addr
        .get(&address)
        .map(|last| now.saturating_sub(*last) < cooldown_ms)
        .unwrap_or(false)
    {
        return false;
    }

    state.admitted_in_window = state.admitted_in_window.saturating_add(1);
    state.last_admit_ms_by_addr.insert(address, now);
    if state.last_admit_ms_by_addr.len() > 50_000 {
        let cutoff = now.saturating_sub(cooldown_ms.saturating_mul(2));
        state.last_admit_ms_by_addr.retain(|_, ts| *ts >= cutoff);
    }

    true
}

fn load_state_mining_enabled() -> bool {
    let war_mode = std::env::var("WAR_MODE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if war_mode {
        return true;
    }
    std::env::var("SCAN_STATE_MINING_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_state_mining_max_per_block() -> usize {
    std::env::var("SCAN_STATE_MINING_MAX_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(50)
}

async fn run_state_mining_cycle(
    sender: &TargetQueueSender,
    queued_in_block: &mut HashSet<Address>,
    _chain_id: u64,
    block_number: u64,
) {
    let max_per_block = load_state_mining_max_per_block();
    if max_per_block == 0 {
        return;
    }

    let cache = high_value_cache();
    if cache.is_empty() {
        return;
    }

    let mut candidates: Vec<Address> = Vec::new();
    // Gather candidates - simple iteration is random enough for DashMap
    for entry in cache.iter() {
        let (is_high_value, _) = *entry.value();
        if is_high_value {
            candidates.push(*entry.key());
        }
    }

    if candidates.is_empty() {
        return;
    }

    // Shuffle or rotate?
    // For now, pseudo-random iteration + truncation.
    // To ensure better coverage over time, we might want a rotating index,
    // but DashMap iteration order changes with capacity changes, so it's "randomish".
    // Let's rely on that + max limit.

    let mut enqueued = 0usize;
    for addr in candidates {
        if enqueued >= max_per_block {
            break;
        }
        if queued_in_block.contains(&addr) {
            continue;
        }

        // Re-verify it's actually high value? No, trust the cache interpretation.
        // It expired? No, we trust the cache (which is TTL managed elsewhere).

        if queued_in_block.insert(addr) {
            // State mining targets are HOT because we explicitly want to check them.
            let _ = sender.enqueue(addr, TargetPriority::Hot).await;
            enqueued += 1;
        }
    }

    if enqueued > 0 {
        tracing::info!(
            "[SCAN] State Mining: Re-queued {} high-value targets for analysis at block #{}.",
            enqueued,
            block_number
        );
    }
}

fn load_lane_semaphore_limit(env_key: &str, default_limit: usize) -> usize {
    std::env::var(env_key)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default_limit)
        .clamp(1, 64)
}

fn tx_by_hash_fallback_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| {
        Arc::new(Semaphore::new(load_lane_semaphore_limit(
            "SCAN_TX_BY_HASH_FALLBACK_SEMAPHORE_LIMIT",
            DEFAULT_FALLBACK_TX_BY_HASH_SEMAPHORE_LIMIT,
        )))
    })
}

fn receipt_fallback_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| {
        Arc::new(Semaphore::new(load_lane_semaphore_limit(
            "SCAN_RECEIPT_FALLBACK_SEMAPHORE_LIMIT",
            DEFAULT_FALLBACK_RECEIPT_SEMAPHORE_LIMIT,
        )))
    })
}

fn linkage_fallback_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| {
        Arc::new(Semaphore::new(load_lane_semaphore_limit(
            "SCAN_LINKAGE_SEMAPHORE_LIMIT",
            DEFAULT_LINKAGE_SEMAPHORE_LIMIT,
        )))
    })
}

fn load_hydration_base_timeout_ms() -> u64 {
    std::env::var("SCAN_HYDRATION_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 250)
        .unwrap_or(DEFAULT_HYDRATION_BASE_TIMEOUT_MS)
}

fn load_timeout_ms(var: &str, default_ms: u64, min_ms: u64, max_ms: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(min_ms, max_ms))
        .unwrap_or(default_ms)
}

fn load_chain_id_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_CHAIN_ID_TIMEOUT_MS",
        DEFAULT_CHAIN_ID_TIMEOUT_MS,
        200,
        30_000,
    )
}

fn load_ws_connect_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_WS_CONNECT_TIMEOUT_MS",
        DEFAULT_WS_CONNECT_TIMEOUT_MS,
        2_000,
        120_000,
    )
}

fn load_ws_subscribe_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_WS_SUBSCRIBE_TIMEOUT_MS",
        DEFAULT_WS_SUBSCRIBE_TIMEOUT_MS,
        2_000,
        60_000,
    )
}

fn load_head_fetch_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_HEAD_FETCH_TIMEOUT_MS",
        DEFAULT_HEAD_FETCH_TIMEOUT_MS,
        250,
        30_000,
    )
}

fn load_hash_mode_block_fetch_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_HASH_MODE_BLOCK_FETCH_TIMEOUT_MS",
        DEFAULT_HASH_MODE_BLOCK_FETCH_TIMEOUT_MS,
        200,
        30_000,
    )
}

fn load_hash_mode_tx_fetch_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_HASH_MODE_TX_FETCH_TIMEOUT_MS",
        DEFAULT_HASH_MODE_TX_FETCH_TIMEOUT_MS,
        200,
        30_000,
    )
}

fn load_hash_mode_receipt_fetch_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_HASH_MODE_RECEIPT_FETCH_TIMEOUT_MS",
        DEFAULT_HASH_MODE_RECEIPT_FETCH_TIMEOUT_MS,
        200,
        30_000,
    )
}

fn load_hash_mode_block_budget_ms() -> u64 {
    load_timeout_ms(
        "SCAN_HASH_MODE_BLOCK_BUDGET_MS",
        DEFAULT_HASH_MODE_BLOCK_BUDGET_MS,
        200,
        30_000,
    )
}

fn load_hash_mode_receipt_fallback_budget_per_block() -> usize {
    std::env::var("SCAN_HASH_MODE_RECEIPT_FALLBACK_BUDGET_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.min(128))
        .unwrap_or(DEFAULT_HASH_MODE_RECEIPT_FALLBACK_BUDGET_PER_BLOCK)
}

fn load_backfill_block_receipts_timeout_ms() -> u64 {
    load_timeout_ms(
        "BACKFILL_BLOCK_RECEIPTS_TIMEOUT_MS",
        DEFAULT_BACKFILL_BLOCK_RECEIPTS_TIMEOUT_MS,
        250,
        60_000,
    )
}

fn load_log_deploy_receipt_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_DEPLOY_RECEIPT_TIMEOUT_MS",
        DEFAULT_LOG_DEPLOY_RECEIPT_TIMEOUT_MS,
        200,
        30_000,
    )
}

fn load_block_worker_concurrency() -> usize {
    std::env::var("SCAN_BLOCK_WORKER_CONCURRENCY")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_BLOCK_WORKER_CONCURRENCY)
}

fn load_skip_on_congestion() -> bool {
    match std::env::var("SCAN_SKIP_ON_CONGESTION") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn load_full_block_ingest_parallelism() -> usize {
    std::env::var("SCAN_FULL_BLOCK_INGEST_PARALLELISM")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, 128))
        .unwrap_or(DEFAULT_FULL_BLOCK_INGEST_PARALLELISM)
}

fn load_full_block_deferred_high_value_probes_per_block() -> usize {
    std::env::var("SCAN_FULL_BLOCK_DEFERRED_HIGH_VALUE_PROBES_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FULL_BLOCK_DEFERRED_HIGH_VALUE_PROBES_PER_BLOCK)
        .min(1_024)
}

fn load_full_block_log_enrichment_enabled() -> bool {
    match std::env::var("SCAN_FULL_BLOCK_LOG_ENRICHMENT_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_full_block_log_enrichment_timeout_ms() -> u64 {
    load_timeout_ms(
        "SCAN_FULL_BLOCK_LOG_ENRICHMENT_TIMEOUT_MS",
        DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_TIMEOUT_MS,
        100,
        5_000,
    )
}

fn load_full_block_log_enrichment_max_addrs_per_block() -> usize {
    std::env::var("SCAN_FULL_BLOCK_LOG_ENRICHMENT_MAX_ADDRS_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_MAX_ADDRS_PER_BLOCK)
        .min(1_024)
}

fn load_full_block_log_enrichment_max_logs_per_block() -> usize {
    std::env::var("SCAN_FULL_BLOCK_LOG_ENRICHMENT_MAX_LOGS_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_MAX_LOGS_PER_BLOCK)
        .clamp(1, 10_000)
}

fn load_full_block_log_enrichment_max_topics_per_log() -> usize {
    std::env::var("SCAN_FULL_BLOCK_LOG_ENRICHMENT_MAX_TOPICS_PER_LOG")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_FULL_BLOCK_LOG_ENRICHMENT_MAX_TOPICS_PER_LOG)
        .clamp(0, 4)
}

fn load_high_value_unknown_admit_budget_per_min() -> usize {
    std::env::var("SCAN_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN)
}

fn load_scanner_min_tvl_usd() -> u128 {
    std::env::var("SCAN_MIN_TVL_USD")
        .ok()
        .and_then(|raw| raw.trim().parse::<u128>().ok())
        .unwrap_or(DEFAULT_WHALE_HUNTING_MIN_TVL_USD)
}

fn load_high_value_unknown_admit_cooldown_ms() -> u64 {
    std::env::var("SCAN_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 1_000)
        .unwrap_or(DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS)
}

fn fast_filter_allow_all_enabled() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var("SCAN_FAST_FILTER_ALLOW_ALL")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

fn load_full_block_hydration_retry_ms() -> u64 {
    std::env::var("SCAN_FULL_BLOCK_HYDRATION_RETRY_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.min(3_600_000))
        .unwrap_or(600_000)
}

fn linkage_discovery_enabled() -> bool {
    std::env::var("SCAN_LINKAGE_DISCOVERY_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn linkage_max_roots_per_block() -> usize {
    std::env::var("SCAN_LINKAGE_MAX_ROOTS_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(0, 64))
        .unwrap_or(4)
}

fn linkage_max_targets_per_root() -> usize {
    std::env::var("SCAN_LINKAGE_MAX_TARGETS_PER_ROOT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(0, 64))
        .unwrap_or(8)
}

fn linkage_high_value_budget_per_block() -> usize {
    std::env::var("SCAN_LINKAGE_DISCOVERY_HIGH_VALUE_BUDGET")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(0, 64))
        .unwrap_or(DEFAULT_LINKAGE_DISCOVERY_HIGH_VALUE_BUDGET)
}

fn is_precompile_address(addr: Address) -> bool {
    let bytes = addr.as_slice();
    if bytes.len() != 20 {
        return false;
    }
    if bytes[0..19].iter().any(|b| *b != 0) {
        return false;
    }
    let last = bytes[19];
    (1..=9).contains(&last)
}

async fn enqueue_linked_contracts<P, T>(
    provider: &Arc<P>,
    sender: &TargetQueueSender,
    root: Address,
    prioritization: PrioritizationConfig,
    queued_targets: &mut HashSet<Address>,
    stats: &mut IngestStats,
) where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if !linkage_discovery_enabled() {
        return;
    }
    if crate::utils::rpc::global_rpc_cooldown_active() {
        return;
    }
    if is_precompile_address(root) || root == Address::ZERO {
        return;
    }

    let budget = if prioritization.high_value_tvl_threshold_wei != U256::ZERO {
        linkage_high_value_budget_per_block()
    } else {
        linkage_max_roots_per_block()
    };
    if budget == 0 || stats.linkage_roots_probed >= budget {
        return;
    }
    stats.linkage_roots_probed = stats.linkage_roots_probed.saturating_add(1);

    // Dedicated linkage lane to avoid starving tx/receipt fallbacks.
    let _permit = match linkage_fallback_semaphore().acquire().await {
        Ok(p) => p,
        Err(_) => return,
    };

    let timeout_ms = load_hydration_base_timeout_ms().clamp(250, 600);
    let code = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        provider.get_code_at(root),
    )
    .await
    {
        Ok(Ok(code)) => code,
        Ok(Err(err)) => {
            is_rate_limited_error(&err.to_string());
            return;
        }
        Err(_) => return,
    };

    if code.is_empty() {
        return;
    }

    let excludes = [root];
    let linked = crate::solver::heuristics::scan_for_call_targets_bytes(code.as_ref(), &excludes);
    if linked.is_empty() {
        return;
    }

    let max_targets = linkage_max_targets_per_root();
    if max_targets == 0 {
        return;
    }

    let mut enqueued = 0usize;
    let min_tvl_limit = min_linkage_tvl_wei();

    for addr in linked.into_iter().take(max_targets) {
        if addr == Address::ZERO || is_precompile_address(addr) {
            continue;
        }

        // Apply the same TVL floor to linked contracts to avoid low-signal dust targets.
        if !min_tvl_limit.is_zero() {
            match provider.get_balance(addr).await {
                Ok(bal) if bal < min_tvl_limit => {
                    continue;
                }
                Ok(_) => {}
                Err(_) => continue, // If balance check fails, safe to skip
            }
        }

        if queued_targets.insert(addr) {
            let _accepted = sender.enqueue(addr, TargetPriority::Dust).await;
            enqueued = enqueued.saturating_add(1);
        }
    }

    stats.linkage_targets_enqueued = stats.linkage_targets_enqueued.saturating_add(enqueued);
}

fn min_linkage_tvl_wei() -> U256 {
    static CACHE: OnceLock<U256> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let min_usd = load_scanner_min_tvl_usd();
        if min_usd == 0 {
            U256::ZERO
        } else {
            let eth_usd = std::env::var("PROFIT_ETH_USD")
                .ok()
                .and_then(|raw| raw.trim().parse::<u128>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(DEFAULT_ETH_USD);
            // (min_usd * 1e18) / eth_usd
            U256::from(min_usd)
                .saturating_mul(U256::from(ONE_ETH_WEI))
                .checked_div(U256::from(eth_usd))
                .unwrap_or(U256::ZERO)
        }
    })
}

fn stable_token_eth_price_wei() -> U256 {
    static CACHE: OnceLock<U256> = OnceLock::new();
    *CACHE.get_or_init(|| {
        if let Ok(raw) = std::env::var("PROFIT_STABLE_TOKEN_ETH_WEI") {
            if let Ok(v) = U256::from_str(raw.trim()) {
                return v;
            }
        }

        let eth_usd = std::env::var("PROFIT_ETH_USD")
            .ok()
            .and_then(|raw| raw.trim().parse::<u128>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_ETH_USD);
        U256::from(ONE_ETH_WEI / eth_usd)
    })
}

fn parse_address_value_csv<T, F>(raw: &str, parse_value: F) -> HashMap<Address, T>
where
    F: Fn(&str) -> Option<T>,
{
    let mut out = HashMap::new();
    for entry in raw.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((addr_raw, value_raw)) = trimmed.split_once('=') else {
            continue;
        };
        let Ok(addr) = Address::from_str(addr_raw.trim()) else {
            continue;
        };
        if let Some(value) = parse_value(value_raw.trim()) {
            out.insert(addr, value);
        }
    }
    out
}

fn parse_u256_decimal(raw: &str) -> Option<U256> {
    U256::from_str(raw.trim()).ok()
}

fn scanner_price_overrides_eth_wei() -> &'static HashMap<Address, U256> {
    static CACHE: OnceLock<HashMap<Address, U256>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = HashMap::new();
        for env_key in [
            "HIGH_VALUE_PRIORITY_TOKEN_PRICES_ETH_WEI",
            "PROFIT_TOKEN_PRICES_ETH_WEI",
        ] {
            if let Ok(raw) = std::env::var(env_key) {
                out.extend(parse_address_value_csv(&raw, parse_u256_decimal));
            }
        }
        out
    })
}

fn scanner_decimal_overrides() -> &'static HashMap<Address, u8> {
    static CACHE: OnceLock<HashMap<Address, u8>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = HashMap::new();
        for env_key in [
            "HIGH_VALUE_PRIORITY_TOKEN_DECIMALS",
            "PROFIT_TOKEN_DECIMALS",
        ] {
            if let Ok(raw) = std::env::var(env_key) {
                out.extend(parse_address_value_csv(&raw, |value| {
                    value.parse::<u8>().ok().filter(|d| *d <= 38)
                }));
            }
        }
        out
    })
}

fn is_known_six_decimal_stable(token: Address) -> bool {
    token == address!("dAC17F958D2ee523a2206206994597C13D831ec7") // mainnet USDT
        || token == address!("Fdc06022312910345eF47F405E524F495145b2f8") // arbitrum USDT
        || token == address!("c2132D05D31c914a87C6611C10748AEb04B58e8F") // polygon USDT
}

fn pow10_u256(exp: u8) -> U256 {
    const MAX_EXP: usize = 38;
    static POW10: OnceLock<Vec<U256>> = OnceLock::new();
    let table = POW10.get_or_init(|| {
        let mut out = Vec::with_capacity(MAX_EXP + 1);
        let mut current = U256::from(1u64);
        out.push(current);
        for _ in 1..=MAX_EXP {
            current = current.saturating_mul(U256::from(10u64));
            out.push(current);
        }
        out
    });
    table
        .get((exp as usize).min(MAX_EXP))
        .copied()
        .unwrap_or(U256::ZERO)
}

fn token_value_eth_wei(balance_raw: U256, price_eth_wei: U256, decimals: u8) -> U256 {
    let scale = pow10_u256(decimals);
    if scale.is_zero() {
        return U256::ZERO;
    }
    balance_raw.saturating_mul(price_eth_wei) / scale
}

fn token_decimals(
    token: Address,
    chain_config: &crate::config::chains::ChainConfig,
    decimal_overrides: &HashMap<Address, u8>,
) -> u8 {
    if let Some(decimals) = decimal_overrides.get(&token) {
        return *decimals;
    }
    if token == chain_config.usdc || is_known_six_decimal_stable(token) {
        6
    } else {
        18
    }
}

fn token_price_eth_wei(
    token: Address,
    chain_config: &crate::config::chains::ChainConfig,
    stable_price_eth_wei: U256,
    price_overrides: &HashMap<Address, U256>,
) -> Option<U256> {
    if let Some(price) = price_overrides.get(&token).copied() {
        return Some(price);
    }
    if token == chain_config.weth {
        return Some(U256::from(ONE_ETH_WEI));
    }
    if token == chain_config.usdc || chain_config.stablecoins.contains(&token) {
        return Some(stable_price_eth_wei);
    }
    None
}

pub fn estimate_contract_tvl_eth_wei(chain_id: u64, balances: &[(Address, U256)]) -> U256 {
    let chain_config = crate::config::chains::ChainConfig::get(chain_id);
    let stable_price_eth_wei = stable_token_eth_price_wei();
    let price_overrides = scanner_price_overrides_eth_wei();
    let decimal_overrides = scanner_decimal_overrides();
    let mut total = U256::ZERO;
    for (token, balance_raw) in balances {
        let Some(price_eth_wei) =
            token_price_eth_wei(*token, &chain_config, stable_price_eth_wei, price_overrides)
        else {
            continue;
        };
        let decimals = token_decimals(*token, &chain_config, decimal_overrides);
        total = total.saturating_add(token_value_eth_wei(*balance_raw, price_eth_wei, decimals));
    }
    total
}

fn load_capital_profiler_enabled() -> bool {
    match std::env::var("CAPITAL_PROFILER_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_capital_profiler_max_addrs_per_block() -> usize {
    std::env::var("CAPITAL_PROFILER_MAX_ADDRS_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_CAPITAL_PROFILER_MAX_ADDRS_PER_BLOCK)
}

fn load_capital_profiler_block_budget_ms() -> u64 {
    std::env::var("CAPITAL_PROFILER_BLOCK_BUDGET_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_CAPITAL_PROFILER_BLOCK_BUDGET_MS)
        .min(5_000)
}

fn load_capital_profiler_carryover_max_addrs() -> usize {
    std::env::var("CAPITAL_PROFILER_CARRYOVER_MAX_ADDRS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_CAPITAL_PROFILER_CARRYOVER_MAX_ADDRS)
        .clamp(32, 20_000)
}

fn load_capital_profiler_max_chunk_calldata_bytes() -> usize {
    std::env::var("CAPITAL_PROFILER_MAX_CHUNK_CALLDATA_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v >= 1_024)
        .unwrap_or(DEFAULT_CAPITAL_PROFILER_MAX_CHUNK_CALLDATA_BYTES)
        .clamp(1_024, 131_072)
}

fn load_capital_profiler_threshold_eth_wei() -> U256 {
    if let Ok(raw) = std::env::var("CAPITAL_PROFILER_THRESHOLD_WEI") {
        match U256::from_str(raw.trim()) {
            Ok(v) => return v,
            Err(_) => {
                eprintln!(
                    "[WARN] Invalid CAPITAL_PROFILER_THRESHOLD_WEI='{}'. Ignoring.",
                    raw
                );
            }
        }
    }

    let usd = match std::env::var("CAPITAL_PROFILER_THRESHOLD_USD") {
        Ok(raw) => match raw.trim().parse::<u128>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "[WARN] Invalid CAPITAL_PROFILER_THRESHOLD_USD='{}'. Using default {}.",
                    raw, DEFAULT_CAPITAL_PROFILER_USD
                );
                DEFAULT_CAPITAL_PROFILER_USD
            }
        },
        Err(_) => DEFAULT_CAPITAL_PROFILER_USD,
    };
    if usd == 0 {
        return U256::ZERO;
    }
    U256::from(usd).saturating_mul(stable_token_eth_price_wei())
}

/// Tokens used for the "Batch Capital Profiler" prioritization signal.
/// Aim: low-RPC, high-signal TVL proxy (WETH + primary stablecoins).
fn build_capital_profiler_tokens(
    chain_config: &crate::config::chains::ChainConfig,
) -> Vec<Address> {
    let mut tokens: Vec<Address> = Vec::with_capacity(3);

    if chain_config.weth != Address::ZERO {
        tokens.push(chain_config.weth);
    }
    if chain_config.usdc != Address::ZERO && !tokens.contains(&chain_config.usdc) {
        tokens.push(chain_config.usdc);
    }
    // Prefer USDT (or any extra stable) when available; Base/Optimism may not have it configured.
    for stable in &chain_config.stablecoins {
        if tokens.len() >= 3 {
            break;
        }
        if *stable != Address::ZERO && !tokens.contains(stable) {
            tokens.push(*stable);
        }
    }

    tokens
}

pub fn capital_profiler_tokens(chain_id: u64) -> Vec<Address> {
    static CACHE: OnceLock<Mutex<HashMap<u64, Vec<Address>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(tokens) = guard.get(&chain_id) {
            return tokens.clone();
        }
    }

    let chain_config = crate::config::chains::ChainConfig::get(chain_id);
    let tokens = build_capital_profiler_tokens(&chain_config);
    if let Ok(mut guard) = cache.lock() {
        guard.insert(chain_id, tokens.clone());
    }
    tokens
}

fn capital_profiler_carryover_queue() -> &'static Mutex<HashMap<u64, VecDeque<Address>>> {
    static QUEUE: OnceLock<Mutex<HashMap<u64, VecDeque<Address>>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn take_capital_profiler_carryover(chain_id: u64, max_take: usize) -> Vec<Address> {
    if max_take == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut guard = match capital_profiler_carryover_queue().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let queue = guard.entry(chain_id).or_default();
    while out.len() < max_take {
        match queue.pop_front() {
            Some(addr) => out.push(addr),
            None => break,
        }
    }
    if queue.is_empty() {
        guard.remove(&chain_id);
    }
    out
}

fn push_capital_profiler_carryover(chain_id: u64, addrs: &[Address], max_queue: usize) {
    if addrs.is_empty() || max_queue == 0 {
        return;
    }
    let mut guard = match capital_profiler_carryover_queue().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let queue = guard.entry(chain_id).or_default();
    let mut seen: HashSet<Address> = queue.iter().copied().collect();
    for addr in addrs.iter().copied() {
        if addr == Address::ZERO {
            continue;
        }
        if !seen.insert(addr) {
            continue;
        }
        queue.push_back(addr);
    }
    while queue.len() > max_queue {
        queue.pop_front();
    }
}

fn load_high_value_tvl_threshold() -> U256 {
    // Direct override: interpret as ETH-wei threshold.
    if let Ok(raw) = std::env::var("HIGH_VALUE_TVL_WEI") {
        match U256::from_str(raw.trim()) {
            Ok(v) => return v,
            Err(_) => {
                eprintln!("[WARN] Invalid HIGH_VALUE_TVL_WEI='{}'. Ignoring.", raw);
            }
        }
    }

    // Default behavior: $-threshold converted into ETH-wei using PROFIT_ETH_USD.
    let usd = match std::env::var("HIGH_VALUE_TVL_USD") {
        Ok(raw) => match raw.trim().parse::<u128>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "[WARN] Invalid HIGH_VALUE_TVL_USD='{}'. Using default {}.",
                    raw, DEFAULT_HIGH_VALUE_TVL_USD
                );
                DEFAULT_HIGH_VALUE_TVL_USD
            }
        },
        Err(_) => DEFAULT_HIGH_VALUE_TVL_USD,
    };
    if usd == 0 {
        return U256::ZERO;
    }

    // Convert USD threshold into ETH-wei using the same stable-token proxy we use for TVL valuation,
    // so a contract holding exactly `$usd` in stablecoins is never incorrectly rejected due to
    // integer-division rounding drift.
    U256::from(usd).saturating_mul(stable_token_eth_price_wei())
}

pub fn high_value_tvl_threshold_wei() -> U256 {
    load_high_value_tvl_threshold()
}

fn load_priority_sequence_indexer_enabled() -> bool {
    match std::env::var("PRIORITY_SEQUENCE_INDEXER_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        // Default OFF: extra polling/decoding can burn RPC quota and add jitter.
        Err(_) => false,
    }
}

fn load_sequencer_ws_ingestion_enabled() -> bool {
    match std::env::var("SEQUENCER_WS_INGESTION_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        // Default ON for OP-Stack chains: this is the latency edge.
        Err(_) => true,
    }
}

fn sequencer_ws_default_max_txs_per_sec(chain_id: u64) -> usize {
    let block_time_ms = crate::config::chains::ChainConfig::get(chain_id)
        .block_time_ms
        .max(250);
    (240_000u64 / block_time_ms).clamp(60, DEFAULT_SEQUENCER_WS_INGESTION_MAX_TXS_PER_SEC as u64)
        as usize
}

fn load_sequencer_ws_ingestion_max_txs_per_sec_for_chain(chain_id: u64) -> usize {
    let default = sequencer_ws_default_max_txs_per_sec(chain_id);
    std::env::var("SEQUENCER_WS_INGESTION_MAX_TXS_PER_SEC")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
        .min(5_000)
}

fn sequencer_ws_default_max_addrs_per_tx(chain_id: u64) -> usize {
    let block_time_ms = crate::config::chains::ChainConfig::get(chain_id)
        .block_time_ms
        .max(250);
    if block_time_ms <= 1_000 {
        DEFAULT_SEQUENCER_WS_INGESTION_MAX_ADDRS_PER_TX
    } else {
        6
    }
}

fn load_sequencer_ws_ingestion_max_addrs_per_tx_for_chain(chain_id: u64) -> usize {
    let default = sequencer_ws_default_max_addrs_per_tx(chain_id);
    std::env::var("SEQUENCER_WS_INGESTION_MAX_ADDRS_PER_TX")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
        .min(64)
}

fn sequencer_ws_default_address_cooldown_ms(chain_id: u64) -> u64 {
    let block_time_ms = crate::config::chains::ChainConfig::get(chain_id)
        .block_time_ms
        .max(250);
    block_time_ms
        .saturating_mul(3)
        .clamp(3_000, DEFAULT_SEQUENCER_WS_INGESTION_ADDRESS_COOLDOWN_MS)
}

fn load_sequencer_ws_ingestion_address_cooldown_ms_for_chain(chain_id: u64) -> u64 {
    let default = sequencer_ws_default_address_cooldown_ms(chain_id);
    std::env::var("SEQUENCER_WS_INGESTION_ADDRESS_COOLDOWN_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 250)
        .unwrap_or(default)
        .min(300_000)
}

fn load_sequencer_ws_ingestion_tracked_addrs_cap(
    max_txs_per_sec: usize,
    addr_cooldown_ms: u64,
) -> usize {
    let derived = max_txs_per_sec
        .saturating_mul(((addr_cooldown_ms / 1_000) as usize).saturating_add(1))
        .saturating_mul(4)
        .clamp(5_000, 100_000);
    std::env::var("SEQUENCER_WS_TRACKED_ADDRS_CAP")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v >= 1_000)
        .unwrap_or(derived)
        .min(200_000)
}

fn load_sequencer_ws_ingestion_allow_hash_fallback() -> bool {
    match std::env::var("SEQUENCER_WS_INGESTION_ALLOW_HASH_FALLBACK") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => DEFAULT_SEQUENCER_WS_INGESTION_ALLOW_HASH_FALLBACK,
    }
}

fn load_sequencer_ws_high_value_probes_per_sec() -> usize {
    std::env::var("SEQUENCER_WS_HIGH_VALUE_PROBES_PER_SEC")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_SEQUENCER_WS_HIGH_VALUE_PROBES_PER_SEC)
        .min(500)
}

fn load_sequencer_ws_high_value_probe_cooldown_ms() -> u64 {
    std::env::var("SEQUENCER_WS_HIGH_VALUE_PROBE_COOLDOWN_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 250)
        .unwrap_or(DEFAULT_SEQUENCER_WS_HIGH_VALUE_PROBE_COOLDOWN_MS)
        .min(300_000)
}

fn load_high_value_probes_per_block() -> usize {
    std::env::var("SCAN_HIGH_VALUE_PROBES_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_HIGH_VALUE_PROBES_PER_BLOCK)
        .clamp(1, 1_000)
}

fn load_high_value_deployment_probes_per_block() -> usize {
    std::env::var("SCAN_HIGH_VALUE_DEPLOYMENT_PROBES_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_HIGH_VALUE_DEPLOYMENT_PROBES_PER_BLOCK)
        .clamp(0, 128)
}

fn load_sequencer_ws_predictive_hydration_enabled() -> bool {
    match std::env::var("SEQUENCER_WS_PREDICTIVE_HYDRATION_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        // Default ON for OP-Stack: intended to provide a pre-block head start.
        Err(_) => true,
    }
}

fn load_sequencer_ws_predictive_hydration_max_tracked() -> usize {
    std::env::var("SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_TRACKED")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_TRACKED)
        .clamp(256, 250_000)
}

fn load_sequencer_ws_predictive_hydration_ttl_ms() -> u64 {
    std::env::var("SEQUENCER_WS_PREDICTIVE_HYDRATION_TTL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_TTL_MS)
        .clamp(5_000, 30 * 60_000)
}

fn load_sequencer_ws_predictive_hydration_max_probes_per_head() -> usize {
    std::env::var("SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_PROBES_PER_HEAD")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_PROBES_PER_HEAD)
        .clamp(1, 5_000)
}

fn load_sequencer_ws_predictive_hydration_code_timeout_ms() -> u64 {
    std::env::var("SEQUENCER_WS_PREDICTIVE_HYDRATION_CODE_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SEQUENCER_WS_PREDICTIVE_HYDRATION_CODE_TIMEOUT_MS)
        .clamp(25, 2_000)
}

pub fn sequencer_ws_ingestion_enabled_for_chain(chain_id: u64) -> bool {
    load_sequencer_ws_ingestion_enabled() && is_opstack_chain(chain_id)
}

fn load_priority_sequence_poll_ms() -> u64 {
    std::env::var("PRIORITY_SEQUENCE_POLL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 100)
        .unwrap_or(DEFAULT_PRIORITY_SEQUENCE_POLL_MS)
}

fn load_priority_sequence_max_txs_per_poll() -> usize {
    std::env::var("PRIORITY_SEQUENCE_MAX_TXS_PER_POLL")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_PRIORITY_SEQUENCE_MAX_TXS_PER_POLL)
}

fn load_priority_sequence_max_addrs_per_tx() -> usize {
    std::env::var("PRIORITY_SEQUENCE_MAX_ADDRS_PER_TX")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_PRIORITY_SEQUENCE_MAX_ADDRS_PER_TX)
}

fn load_priority_sequence_address_cooldown_ms() -> u64 {
    std::env::var("PRIORITY_SEQUENCE_ADDRESS_COOLDOWN_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 1_000)
        .unwrap_or(DEFAULT_PRIORITY_SEQUENCE_ADDRESS_COOLDOWN_MS)
}

fn load_public_ws_race_channel_capacity() -> usize {
    std::env::var("SCAN_PUBLIC_WS_RACE_CHANNEL_CAPACITY")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_PUBLIC_WS_RACE_CHANNEL_CAPACITY)
        .clamp(256, 65_536)
}

fn load_public_ws_race_urls(primary_ws_url: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = HashSet::<String>::new();
    let primary_trimmed = primary_ws_url.trim();
    if !primary_trimmed.is_empty() {
        urls.push(primary_trimmed.to_string());
        seen.insert(primary_trimmed.to_string());
    }

    let Ok(raw) = std::env::var("SCAN_PUBLIC_WS_RACE_URLS") else {
        return urls;
    };
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            urls.push(trimmed.to_string());
        }
    }
    urls
}

fn adaptive_hydration_timeout_ms(base_ms: u64) -> u64 {
    let tx_hint = LAST_HYDRATED_BLOCK_TX_COUNT.load(Ordering::Relaxed);
    let scaled = if tx_hint >= 300 {
        base_ms.saturating_mul(2)
    } else if tx_hint >= 200 {
        base_ms.saturating_mul(3) / 2
    } else if tx_hint >= 120 {
        base_ms.saturating_mul(5) / 4
    } else {
        base_ms
    };
    scaled.clamp(base_ms, 60_000)
}

fn configured_opstack_chain_ids() -> &'static HashSet<u64> {
    static IDS: OnceLock<HashSet<u64>> = OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids = HashSet::from([8453_u64, 10_u64]);
        if let Ok(raw) = std::env::var("OPSTACK_CHAIN_IDS") {
            for token in raw.split(',') {
                let trimmed = token.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match trimmed.parse::<u64>() {
                    Ok(v) => {
                        ids.insert(v);
                    }
                    Err(_) => warn_scan_throttled(format!(
                        "[SCAN] Ignoring invalid OPSTACK_CHAIN_IDS entry `{}`.",
                        trimmed
                    )),
                }
            }
        }
        ids
    })
}

fn is_opstack_chain(chain_id: u64) -> bool {
    configured_opstack_chain_ids().contains(&chain_id)
}

fn parse_address_hex(raw: &str) -> Option<Address> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0x" {
        return None;
    }
    Address::from_str(trimmed).ok()
}

fn parse_bytes_hex(raw: &str) -> Option<Bytes> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "0x" {
        return Some(Bytes::new());
    }
    match Bytes::from_str(trimmed) {
        Ok(v) => Some(v),
        Err(_) => {
            warn_scan_throttled(format!(
                "[SCAN] Ignoring invalid hex input in pending tx candidate: `{}`",
                trimmed
            ));
            None
        }
    }
}

fn extract_abi_addresses(input: &Bytes, max_addrs: usize) -> Vec<Address> {
    if input.len() < 4 + 32 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(max_addrs.min(8));
    let mut i = 4usize;
    while i + 32 <= input.len() && out.len() < max_addrs {
        let word = &input[i..i + 32];
        // ABI-encoded addresses are 20 bytes right-aligned with 12 bytes leading zeros.
        if word[0..12].iter().all(|b| *b == 0) {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&word[12..32]);
            let parsed = Address::from(addr);
            if parsed != Address::ZERO && !out.contains(&parsed) {
                out.push(parsed);
            }
        }
        i += 32;
    }
    out
}

fn extract_packed_path_addresses(input: &Bytes, max_addrs: usize) -> Vec<Address> {
    if max_addrs == 0 || input.len() < 4 + 43 {
        return Vec::new();
    }
    // Bound scan work for unusually large calldata.
    let scan_limit = input.len().min(2_048);
    let bytes = &input[..scan_limit];
    let mut out = Vec::with_capacity(max_addrs.min(8));
    let mut i = 4usize;
    while i + 43 <= bytes.len() && out.len() < max_addrs {
        // Packed V3-style path candidate: token(20) + fee(3) + token(20)
        let fee =
            ((bytes[i + 20] as u32) << 16) | ((bytes[i + 21] as u32) << 8) | bytes[i + 22] as u32;
        if (100..=1_000_000).contains(&fee) {
            let a = Address::from_slice(&bytes[i..i + 20]);
            let b = Address::from_slice(&bytes[i + 23..i + 43]);
            if a != Address::ZERO && !out.contains(&a) {
                out.push(a);
                if out.len() >= max_addrs {
                    break;
                }
            }
            if b != Address::ZERO && !out.contains(&b) {
                out.push(b);
                if out.len() >= max_addrs {
                    break;
                }
            }
            // Advance one packed hop (20-byte addr + 3-byte fee) when matched.
            i = i.saturating_add(23);
            continue;
        }
        i = i.saturating_add(1);
    }
    out
}

fn topic_indexed_address(topic: &B256) -> Option<Address> {
    let bytes = topic.as_slice();
    // Indexed address topics are 32-byte ABI words with 12 leading zero bytes.
    if bytes[0..12].iter().any(|b| *b != 0) {
        return None;
    }
    let addr = Address::from_slice(&bytes[12..32]);
    if addr == Address::ZERO || is_precompile_address(addr) {
        return None;
    }
    Some(addr)
}

fn push_log_enriched_candidate(
    addr: Address,
    enriched: &mut HashSet<Address>,
    interesting_addrs: &mut Vec<Address>,
    log_enrichment_hits: &mut usize,
) {
    if addr == Address::ZERO || is_precompile_address(addr) {
        return;
    }
    if enriched.insert(addr) {
        interesting_addrs.push(addr);
        *log_enrichment_hits = log_enrichment_hits.saturating_add(1);
    }
}

fn rlp_encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        out.push(bytes[0]);
        return;
    }
    if bytes.len() <= 55 {
        out.push(0x80u8 + bytes.len() as u8);
        out.extend_from_slice(bytes);
        return;
    }
    // Long form: 0xb7 + len(len) followed by len bytes.
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&(bytes.len() as u64).to_be_bytes());
    let first = len_buf.iter().position(|b| *b != 0).unwrap_or(7);
    let len_bytes = &len_buf[first..];
    out.push(0xb7u8 + len_bytes.len() as u8);
    out.extend_from_slice(len_bytes);
    out.extend_from_slice(bytes);
}

fn rlp_encode_u64(out: &mut Vec<u8>, value: u64) {
    if value == 0 {
        out.push(0x80);
        return;
    }
    if value < 128 {
        out.push(value as u8);
        return;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&value.to_be_bytes());
    let first = buf.iter().position(|b| *b != 0).unwrap_or(7);
    let slice = &buf[first..];
    out.push(0x80u8 + slice.len() as u8);
    out.extend_from_slice(slice);
}

fn predict_create_address(from: Address, nonce: u64) -> Address {
    let mut payload = Vec::with_capacity(1 + 1 + 20 + 1 + 8);
    // address
    rlp_encode_bytes(&mut payload, from.as_slice());
    // nonce
    rlp_encode_u64(&mut payload, nonce);

    let mut list = Vec::with_capacity(1 + payload.len());
    if payload.len() <= 55 {
        list.push(0xc0u8 + payload.len() as u8);
    } else {
        // Not expected; keep conservative.
        list.push(0xf7);
    }
    list.extend_from_slice(&payload);

    let hash = keccak256(&list);
    Address::from_slice(&hash[12..32])
}

fn predict_create2_address(deployer: Address, salt: [u8; 32], init_code: &[u8]) -> Address {
    let init_hash = keccak256(init_code);
    let mut buf = Vec::with_capacity(1 + 20 + 32 + 32);
    buf.push(0xff);
    buf.extend_from_slice(deployer.as_slice());
    buf.extend_from_slice(&salt);
    buf.extend_from_slice(init_hash.as_slice());
    let hash = keccak256(&buf);
    Address::from_slice(&hash[12..32])
}

fn predict_eip2470_singleton_factory_create2(input: &Bytes) -> Option<Address> {
    // deploy(bytes,bytes32)
    if input.len() < 4 + 64 {
        return None;
    }
    let sig = keccak256("deploy(bytes,bytes32)".as_bytes());
    if input[0..4] != sig[0..4] {
        return None;
    }

    let base = 4usize;
    let offset_word = &input[base..base + 32];
    let offset = U256::from_be_slice(offset_word).to::<u64>() as usize;
    let salt_word = &input[base + 32..base + 64];
    let mut salt = [0u8; 32];
    salt.copy_from_slice(salt_word);

    let data_start = base.saturating_add(offset);
    if data_start + 32 > input.len() {
        return None;
    }
    let len_word = &input[data_start..data_start + 32];
    let len = U256::from_be_slice(len_word).to::<u64>() as usize;
    let data = data_start + 32;
    if data + len > input.len() {
        return None;
    }
    let init_code = &input[data..data + len];
    if init_code.is_empty() {
        return None;
    }
    Some(predict_create2_address(
        EIP2470_SINGLETON_FACTORY,
        salt,
        init_code,
    ))
}

async fn spawn_sequencer_ws_ingestion_task<P, T>(
    provider: Arc<P>,
    sender: TargetQueueSender,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    chain_id: u64,
    high_value_tvl_threshold_wei: U256,
) where
    P: Provider<T> + 'static,
    T: alloy::transports::Transport + Clone + 'static,
{
    if !sequencer_ws_ingestion_enabled_for_chain(chain_id) {
        return;
    }

    let max_txs_per_sec = load_sequencer_ws_ingestion_max_txs_per_sec_for_chain(chain_id);
    let max_addrs_per_tx = load_sequencer_ws_ingestion_max_addrs_per_tx_for_chain(chain_id);
    let addr_cooldown_ms = load_sequencer_ws_ingestion_address_cooldown_ms_for_chain(chain_id);
    let tracked_addrs_cap =
        load_sequencer_ws_ingestion_tracked_addrs_cap(max_txs_per_sec, addr_cooldown_ms);
    let allow_hash_fallback = load_sequencer_ws_ingestion_allow_hash_fallback();
    let max_high_value_probes_per_sec = load_sequencer_ws_high_value_probes_per_sec();
    let high_value_probe_cooldown_ms = load_sequencer_ws_high_value_probe_cooldown_ms();

    tracing::info!(
        "[SEQWS] Sequencer WS ingestion enabled: max_txs_per_sec={} max_addrs_per_tx={} cooldown={}ms tracked_addrs_cap={} hash_fallback={}",
        max_txs_per_sec,
        max_addrs_per_tx,
        addr_cooldown_ms,
        tracked_addrs_cap,
        allow_hash_fallback
    );

    tokio::spawn(async move {
        let mut last_sent_ms: HashMap<Address, u64> = HashMap::new();
        let mut last_probe_ms: HashMap<Address, u64> = HashMap::new();
        let predicted_deployments: Arc<Mutex<HashMap<Address, PredictedDeployment>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut window_start_ms = now_ms();
        let mut txs_in_window: usize = 0;
        let mut probes_in_window: usize = 0;
        let mut last_log = Instant::now();
        let mut total_seen: u64 = 0;
        let mut total_enqueued: u64 = 0;

        // Prefer full pending transaction bodies; this is the intended low-RPC "pending stream".
        let mut full_stream = match provider.subscribe_full_pending_transactions().await {
            Ok(sub) => Some(sub.into_stream()),
            Err(err) => {
                warn_scan_throttled(format!(
                    "[SEQWS] subscribe_full_pending_transactions failed: {}",
                    compact_error(err)
                ));
                None
            }
        };

        // Hash-only fallback is dangerous (requires per-hash fetch). Keep it opt-in.
        let mut hash_stream = if full_stream.is_none() && allow_hash_fallback {
            match provider.subscribe_pending_transactions().await {
                Ok(sub) => Some(sub.into_stream()),
                Err(err) => {
                    warn_scan_throttled(format!(
                        "[SEQWS] subscribe_pending_transactions fallback failed: {}",
                        compact_error(err)
                    ));
                    None
                }
            }
        } else {
            None
        };

        if full_stream.is_none() && hash_stream.is_none() {
            warn_scan_throttled(
                "[SEQWS] Pending-tx subscription unavailable; sequencer WS ingestion disabled."
                    .to_string(),
            );
            return;
        }

        if load_sequencer_ws_predictive_hydration_enabled() {
            let provider_probe = provider.clone();
            let sender_probe = sender.clone();
            let predicted_probe = predicted_deployments.clone();
            let mut shutdown_probe = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let sub = match provider_probe.subscribe_blocks().await {
                    Ok(sub) => sub,
                    Err(err) => {
                        warn_scan_throttled(format!(
                            "[HYDRATE] Predictive head subscription unavailable: {}",
                            compact_error(err)
                        ));
                        return;
                    }
                };
                let mut stream = sub.into_stream();
                loop {
                    tokio::select! {
                        _ = shutdown_probe.recv() => break,
                        maybe_block = stream.next() => {
                            let Some(_block) = maybe_block else { continue; };
                            if crate::utils::rpc::global_rpc_cooldown_active() {
                                continue;
                            }

                            let now = now_ms();
                            let ttl_ms = load_sequencer_ws_predictive_hydration_ttl_ms();
                            let max_probes = load_sequencer_ws_predictive_hydration_max_probes_per_head();
                            let timeout_ms = load_sequencer_ws_predictive_hydration_code_timeout_ms();

                            let addrs: Vec<Address> = {
                                let mut guard = match predicted_probe.lock() {
                                    Ok(g) => g,
                                    Err(p) => p.into_inner(),
                                };
                                let cutoff = now.saturating_sub(ttl_ms);
                                guard.retain(|_, v| v.last_seen_ms >= cutoff);
                                guard.keys().take(max_probes).copied().collect()
                            };

                            for addr in addrs {
                                let code = match tokio::time::timeout(
                                    Duration::from_millis(timeout_ms),
                                    provider_probe.get_code_at(addr),
                                )
                                .await
                                {
                                    Ok(Ok(code)) => code,
                                    _ => continue,
                                };
                                if code.is_empty() {
                                    continue;
                                }

                                let _accepted = sender_probe.enqueue(addr, TargetPriority::Hot).await;
                                {
                                    let mut guard = match predicted_probe.lock() {
                                        Ok(g) => g,
                                        Err(p) => p.into_inner(),
                                    };
                                    if let Some(entry) = guard.remove(&addr) {
                                        let age_ms = now.saturating_sub(entry.first_seen_ms);
                                        let kind = match entry.kind {
                                            PredictedDeploymentKind::Create => "create",
                                            PredictedDeploymentKind::Create2SingletonFactory => {
                                                "create2_singleton_factory"
                                            }
                                        };
                                        tracing::info!(
                                            "[HYDRATE] Predicted {} deployment materialized: addr={:#x} age_ms={} from={:#x} nonce={}",
                                            kind,
                                            addr,
                                            age_ms,
                                            entry.from,
                                            entry.nonce
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }

        loop {
            if let Some(stream) = full_stream.as_mut() {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("[SEQWS] Shutdown signal received. Stopping sequencer WS ingestion...");
                        break;
                    }
                    maybe_tx = stream.next() => {
                        let Some(tx) = maybe_tx else { continue; };
                        let to = tx.to();
                        process_pending_tx_candidate(
                            provider.as_ref(),
                            &sender,
                            Some(&predicted_deployments),
                            &mut last_sent_ms,
                            &mut last_probe_ms,
                            &mut window_start_ms,
                            &mut txs_in_window,
                            &mut probes_in_window,
                            &mut total_seen,
                            &mut total_enqueued,
                            &mut last_log,
                            Some(tx.from()),
                            Some(tx.nonce()),
                            tx.is_create(),
                            to,
                            tx.input(),
                            chain_id,
                            max_txs_per_sec,
                            max_addrs_per_tx,
                            addr_cooldown_ms,
                            tracked_addrs_cap,
                            high_value_tvl_threshold_wei,
                            max_high_value_probes_per_sec,
                            high_value_probe_cooldown_ms,
                        )
                        .await;
                    }
                }
            } else if let Some(stream) = hash_stream.as_mut() {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("[SEQWS] Shutdown signal received. Stopping sequencer WS ingestion...");
                        break;
                    }
                    maybe_hash = stream.next() => {
                        let Some(hash) = maybe_hash else { continue; };
                        let now = now_ms();
                        if now.saturating_sub(window_start_ms) >= 1_000 {
                            window_start_ms = now;
                            txs_in_window = 0;
                            probes_in_window = 0;
                        }
                        if txs_in_window >= max_txs_per_sec {
                            continue;
                        }

                        let fetched = match tokio::time::timeout(Duration::from_millis(200), async {
                            provider.get_transaction_by_hash(hash).await
                        })
                        .await
                        {
                            Ok(res) => res,
                            Err(_) => continue,
                        };
                        let Some(tx) = (match fetched {
                            Ok(tx) => tx,
                            Err(_) => continue,
                        }) else {
                            continue;
                        };
                        let to = tx.to();
                        process_pending_tx_candidate(
                            provider.as_ref(),
                            &sender,
                            Some(&predicted_deployments),
                            &mut last_sent_ms,
                            &mut last_probe_ms,
                            &mut window_start_ms,
                            &mut txs_in_window,
                            &mut probes_in_window,
                            &mut total_seen,
                            &mut total_enqueued,
                            &mut last_log,
                            Some(tx.from()),
                            Some(tx.nonce()),
                            tx.is_create(),
                            to,
                            tx.input(),
                            chain_id,
                            max_txs_per_sec,
                            max_addrs_per_tx,
                            addr_cooldown_ms,
                            tracked_addrs_cap,
                            high_value_tvl_threshold_wei,
                            max_high_value_probes_per_sec,
                            high_value_probe_cooldown_ms,
                        )
                        .await;
                    }
                }
            } else {
                break;
            }
        }
    });
}

async fn pending_high_value_probe<P, T>(
    provider: &P,
    address: Address,
    chain_id: u64,
    threshold_wei: U256,
) -> bool
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if threshold_wei == U256::ZERO {
        return true;
    }
    if crate::utils::rpc::global_rpc_cooldown_active() {
        return false;
    }

    // Quick code check to avoid probing EOAs.
    let code = match tokio::time::timeout(Duration::from_millis(150), provider.get_code_at(address))
        .await
    {
        Ok(Ok(code)) => code,
        _ => return false,
    };
    if code.is_empty() {
        record_target_capital_estimate(address, U256::ZERO);
        return false;
    }

    let mut total_eth_wei =
        match tokio::time::timeout(Duration::from_millis(150), provider.get_balance(address)).await
        {
            Ok(Ok(v)) => v,
            _ => U256::ZERO,
        };
    record_target_capital_estimate(address, total_eth_wei);
    if total_eth_wei >= threshold_wei {
        return true;
    }

    let tokens = capital_profiler_tokens(chain_id);
    if tokens.is_empty() {
        return false;
    }

    let calldata = balance_of_calldata(address);
    let calls = tokens
        .iter()
        .map(|token| Multicall3Call {
            target: *token,
            allowFailure: true,
            callData: calldata.clone(),
        })
        .collect::<Vec<_>>();
    let Some(multicall_addr) = multicall3_address_for_chain(chain_id).or_else(multicall3_address)
    else {
        return false;
    };
    let req = alloy::rpc::types::TransactionRequest::default()
        .to(multicall_addr)
        .input(alloy::rpc::types::TransactionInput::new(
            aggregate3Call { calls }.abi_encode().into(),
        ));
    let multicall_result = tokio::time::timeout(Duration::from_millis(250), provider.call(&req))
        .await
        .ok()
        .and_then(|res| res.ok())
        .and_then(|raw| decode_multicall_balance_results(&tokens, raw.as_ref()));
    if let Some(balances) = multicall_result {
        total_eth_wei =
            total_eth_wei.saturating_add(estimate_contract_tvl_eth_wei(chain_id, &balances));
        record_target_capital_estimate(address, total_eth_wei);
        return total_eth_wei >= threshold_wei;
    }

    false
}

#[allow(clippy::too_many_arguments)]
async fn process_pending_tx_candidate<P, T>(
    provider: &P,
    sender: &TargetQueueSender,
    predicted_deployments: Option<&Arc<Mutex<HashMap<Address, PredictedDeployment>>>>,
    last_sent_ms: &mut HashMap<Address, u64>,
    last_probe_ms: &mut HashMap<Address, u64>,
    window_start_ms: &mut u64,
    txs_in_window: &mut usize,
    probes_in_window: &mut usize,
    total_seen: &mut u64,
    total_enqueued: &mut u64,
    last_log: &mut Instant,
    from: Option<Address>,
    nonce: Option<u64>,
    is_create: bool,
    to: Option<Address>,
    input: &Bytes,
    chain_id: u64,
    max_txs_per_sec: usize,
    max_addrs_per_tx: usize,
    addr_cooldown_ms: u64,
    tracked_addrs_cap: usize,
    high_value_tvl_threshold_wei: U256,
    max_high_value_probes_per_sec: usize,
    high_value_probe_cooldown_ms: u64,
) where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let now = now_ms();
    if now.saturating_sub(*window_start_ms) >= 1_000 {
        *window_start_ms = now;
        *txs_in_window = 0;
        *probes_in_window = 0;
    }
    if *txs_in_window >= max_txs_per_sec {
        return;
    }
    *txs_in_window = txs_in_window.saturating_add(1);
    *total_seen = total_seen.saturating_add(1);

    if last_sent_ms.len() > tracked_addrs_cap.saturating_mul(2) {
        last_sent_ms.retain(|_, t| now.saturating_sub(*t) < addr_cooldown_ms.saturating_mul(4));
    }
    if last_probe_ms.len() > tracked_addrs_cap.saturating_mul(2) {
        last_probe_ms
            .retain(|_, t| now.saturating_sub(*t) < high_value_probe_cooldown_ms.saturating_mul(4));
    }

    if let Some(predicted) = predicted_deployments {
        if load_sequencer_ws_predictive_hydration_enabled() {
            let mut candidates = Vec::new();
            if is_create {
                if let (Some(from), Some(nonce)) = (from, nonce) {
                    candidates.push((
                        predict_create_address(from, nonce),
                        PredictedDeploymentKind::Create,
                        from,
                        nonce,
                    ));
                }
            } else if to == Some(EIP2470_SINGLETON_FACTORY) {
                if let (Some(from), Some(nonce)) = (from, nonce) {
                    if let Some(predicted_addr) = predict_eip2470_singleton_factory_create2(input) {
                        candidates.push((
                            predicted_addr,
                            PredictedDeploymentKind::Create2SingletonFactory,
                            from,
                            nonce,
                        ));
                    }
                }
            }

            if !candidates.is_empty() {
                let max_tracked = load_sequencer_ws_predictive_hydration_max_tracked();
                let ttl_ms = load_sequencer_ws_predictive_hydration_ttl_ms();
                let mut guard = match predicted.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                if guard.len() > max_tracked.saturating_mul(2) {
                    let cutoff = now.saturating_sub(ttl_ms);
                    guard.retain(|_, v| v.last_seen_ms >= cutoff);
                }
                if guard.len() < max_tracked {
                    for (addr, kind, from, nonce) in candidates {
                        let entry = guard.entry(addr).or_insert(PredictedDeployment {
                            kind,
                            first_seen_ms: now,
                            last_seen_ms: now,
                            from,
                            nonce,
                        });
                        entry.last_seen_ms = now;
                    }
                }
            }
        }
    }

    if !FastFilter::is_interesting(to, input) {
        return;
    }

    let mut candidates: Vec<Address> = Vec::with_capacity(max_addrs_per_tx.saturating_add(1));
    if let Some(to_addr) = to {
        candidates.push(to_addr);
    }
    for addr in extract_abi_addresses(input, max_addrs_per_tx) {
        if !candidates.contains(&addr) {
            candidates.push(addr);
        }
    }
    for addr in extract_packed_path_addresses(input, max_addrs_per_tx) {
        if !candidates.contains(&addr) {
            candidates.push(addr);
        }
    }

    for addr in candidates {
        if last_sent_ms.len() >= tracked_addrs_cap && !last_sent_ms.contains_key(&addr) {
            continue;
        }
        let recently_sent = last_sent_ms
            .get(&addr)
            .map(|prev| now.saturating_sub(*prev) < addr_cooldown_ms)
            .unwrap_or(false);
        if recently_sent {
            continue;
        }

        if high_value_tvl_threshold_wei != U256::ZERO {
            let allow_cached = target_capital_estimate_eth_wei(addr)
                .map(|v| v >= high_value_tvl_threshold_wei)
                .unwrap_or(false);
            let allow = if allow_cached {
                true
            } else {
                let probe_cooldown_ms = high_value_probe_cooldown_ms;
                let recently_probed = last_probe_ms
                    .get(&addr)
                    .map(|prev| now.saturating_sub(*prev) < probe_cooldown_ms)
                    .unwrap_or(false);
                if recently_probed
                    || *probes_in_window >= max_high_value_probes_per_sec
                    || (last_probe_ms.len() >= tracked_addrs_cap
                        && !last_probe_ms.contains_key(&addr))
                {
                    false
                } else {
                    last_probe_ms.insert(addr, now);
                    *probes_in_window = probes_in_window.saturating_add(1);
                    pending_high_value_probe(provider, addr, chain_id, high_value_tvl_threshold_wei)
                        .await
                }
            };
            if !allow {
                continue;
            }
        }

        last_sent_ms.insert(addr, now);

        if last_sent_ms.len() > tracked_addrs_cap {
            last_sent_ms.retain(|_, t| now.saturating_sub(*t) < addr_cooldown_ms.saturating_mul(4));
        }
        if last_probe_ms.len() > tracked_addrs_cap {
            last_probe_ms.retain(|_, t| {
                now.saturating_sub(*t) < high_value_probe_cooldown_ms.saturating_mul(4)
            });
        }

        let _accepted = sender.enqueue(addr, TargetPriority::Hot).await;
        *total_enqueued = total_enqueued.saturating_add(1);
    }

    if last_log.elapsed() >= Duration::from_secs(10) {
        tracing::info!(
            "[SEQWS] seen={} enqueued={} tracked_addrs={} tracked_cap={} window_txs={} max_txs_per_sec={}",
            total_seen,
            total_enqueued,
            last_sent_ms.len(),
            tracked_addrs_cap,
            txs_in_window,
            max_txs_per_sec
        );
        *last_log = Instant::now();
    }
}

/// Priority Sequence Indexer (OP-Stack):
/// Poll the pending block and enqueue candidate target addresses before they land on-chain.
///
/// This is a "ghost liquidity" signal: for centralized sequencers, pending tx order often
/// reflects imminent state changes even before a canonical block is published.
pub async fn start_priority_sequence_indexer(
    rpc_url: &str,
    target_sender: TargetQueueSender,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    if !load_priority_sequence_indexer_enabled() {
        tracing::info!("[PRIORITY] Disabled by PRIORITY_SEQUENCE_INDEXER_ENABLED.");
        return Ok(());
    }

    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
    let provider = Arc::new(provider);
    let chain_id = match tokio::time::timeout(
        Duration::from_millis(load_chain_id_timeout_ms()),
        provider.get_chain_id(),
    )
    .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(err)) => {
            return Err(anyhow::anyhow!(
                "[PRIORITY] Failed to fetch chain id: {}",
                compact_error(err)
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "[PRIORITY] Timed out fetching chain id after {}ms.",
                load_chain_id_timeout_ms()
            ));
        }
    };
    if !is_opstack_chain(chain_id) {
        tracing::info!(
            "[PRIORITY] Skipping priority sequence indexer for chain_id={}.",
            chain_id
        );
        return Ok(());
    }
    if sequencer_ws_ingestion_enabled_for_chain(chain_id) {
        tracing::info!(
            "[PRIORITY] Sequencer WS ingestion enabled; skipping pending-block polling indexer."
        );
        return Ok(());
    }

    let poll_ms = load_priority_sequence_poll_ms();
    let max_txs = load_priority_sequence_max_txs_per_poll();
    let max_addrs = load_priority_sequence_max_addrs_per_tx();
    let addr_cooldown_ms = load_priority_sequence_address_cooldown_ms();

    tracing::info!(
        "[PRIORITY] OP-Stack pending indexer enabled: poll={}ms max_txs_per_poll={} max_addrs_per_tx={} cooldown={}ms",
        poll_ms,
        max_txs,
        max_addrs,
        addr_cooldown_ms
    );

    let mut last_sent_ms: HashMap<Address, u64> = HashMap::new();
    let mut last_log = Instant::now();
    let mut last_pending_number: Option<u64> = None;
    let mut total_enqueued: u64 = 0;

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("[PRIORITY] Shutdown signal received. Stopping priority indexer...");
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(poll_ms)) => {}
        }

        if crate::utils::rpc::global_rpc_cooldown_active() {
            continue;
        }

        // NOTE: Use raw_request to avoid typed decoding brittleness for pending blocks.
        let pending = match tokio::time::timeout(
            Duration::from_millis(800),
            provider.raw_request::<_, serde_json::Value>(
                std::borrow::Cow::Borrowed("eth_getBlockByNumber"),
                serde_json::json!(["pending", true]),
            ),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(err)) => {
                warn_scan_throttled(format!(
                    "[PRIORITY] pending block fetch error: {}",
                    compact_error(err)
                ));
                continue;
            }
            Err(_) => continue,
        };

        let pending_number = pending
            .get("number")
            .and_then(|v| v.as_str())
            .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok());
        if pending_number.is_some() && pending_number == last_pending_number {
            // Avoid re-processing identical pending head when sequencer hasn't advanced.
            continue;
        }
        last_pending_number = pending_number;

        let Some(txs) = pending.get("transactions").and_then(|v| v.as_array()) else {
            continue;
        };

        let now_ms = now_ms();
        let mut poll_targets: HashSet<Address> = HashSet::new();
        for tx in txs.iter().take(max_txs) {
            let to = tx
                .get("to")
                .and_then(|v| v.as_str())
                .and_then(parse_address_hex);
            let input = tx
                .get("input")
                .and_then(|v| v.as_str())
                .and_then(parse_bytes_hex)
                .unwrap_or_else(Bytes::new);

            if !FastFilter::is_interesting(to, &input) {
                continue;
            }

            if let Some(to_addr) = to {
                poll_targets.insert(to_addr);
            }
            for addr in extract_abi_addresses(&input, max_addrs) {
                poll_targets.insert(addr);
            }
        }

        for addr in poll_targets {
            let recently_sent = last_sent_ms
                .get(&addr)
                .map(|prev| now_ms.saturating_sub(*prev) < addr_cooldown_ms)
                .unwrap_or(false);
            if recently_sent {
                continue;
            }
            last_sent_ms.insert(addr, now_ms);

            // Bound memory growth: prune map opportunistically.
            if last_sent_ms.len() > 50_000 {
                last_sent_ms
                    .retain(|_, t| now_ms.saturating_sub(*t) < addr_cooldown_ms.saturating_mul(4));
            }

            let _accepted = target_sender.enqueue(addr, TargetPriority::Hot).await;
            total_enqueued = total_enqueued.saturating_add(1);
        }

        if last_log.elapsed() >= Duration::from_secs(10) {
            tracing::info!(
                "[PRIORITY] pending head={:?} total_enqueued={} tracked_addrs={}",
                last_pending_number,
                total_enqueued,
                last_sent_ms.len()
            );
            last_log = Instant::now();
        }
    }

    Ok(())
}

fn top_priority_tokens(chain_id: u64) -> Vec<Address> {
    static CACHE: OnceLock<DashMap<u64, Vec<Address>>> = OnceLock::new();
    let cache = CACHE.get_or_init(DashMap::new);
    if let Some(hit) = cache.get(&chain_id) {
        return hit.value().clone();
    }

    let chain_config = crate::config::chains::ChainConfig::get(chain_id);
    let stable_price_eth_wei = stable_token_eth_price_wei();
    let price_overrides = scanner_price_overrides_eth_wei();

    let mut tokens = Vec::new();
    for token in chain_config.known_tokens.iter().copied() {
        if token == Address::ZERO {
            continue;
        }
        if token_price_eth_wei(token, &chain_config, stable_price_eth_wei, price_overrides)
            .is_some()
            && !tokens.contains(&token)
        {
            tokens.push(token);
        }
    }
    if let Ok(raw) = std::env::var("HIGH_VALUE_PRIORITY_TOKENS") {
        for item in raw.split(',') {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                continue;
            }
            match Address::from_str(trimmed) {
                Ok(token) => {
                    if token == Address::ZERO {
                        continue;
                    }
                    if token_price_eth_wei(
                        token,
                        &chain_config,
                        stable_price_eth_wei,
                        price_overrides,
                    )
                    .is_none()
                    {
                        warn_scan_throttled(format!(
                            "[SCAN] Ignoring unpriced HIGH_VALUE_PRIORITY_TOKENS entry `{}` (set HIGH_VALUE_PRIORITY_TOKEN_PRICES_ETH_WEI or PROFIT_TOKEN_PRICES_ETH_WEI).",
                            trimmed
                        ));
                        continue;
                    }
                    if !tokens.contains(&token) {
                        tokens.push(token);
                    }
                }
                Err(_) => {
                    warn_scan_throttled(format!(
                        "[SCAN] Ignoring invalid HIGH_VALUE_PRIORITY_TOKENS entry `{}`.",
                        trimmed
                    ));
                }
            }
        }
    }
    tokens.truncate(10);
    cache.insert(chain_id, tokens.clone());
    tokens
}

fn balance_of_calldata(owner: Address) -> Bytes {
    let mut call_data = [0u8; 36];
    call_data[0..4].copy_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
    // ABI-encoded address word is 12 leading zero bytes + 20-byte address.
    call_data[16..36].copy_from_slice(owner.as_slice());
    Bytes::copy_from_slice(&call_data)
}

fn multicall3_address() -> Option<Address> {
    let chain_id = std::env::var("CHAIN_ID").ok()?.trim().parse::<u64>().ok()?;
    multicall3_address_for_chain(chain_id)
}

fn multicall3_address_for_chain(chain_id: u64) -> Option<Address> {
    if let Ok(raw) = std::env::var(format!("MULTICALL3_ADDRESS_{chain_id}")) {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("disabled") {
            return None;
        }
        return Address::from_str(trimmed).ok();
    }
    if let Ok(raw) = std::env::var("MULTICALL3_ADDRESS") {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("none") || trimmed.eq_ignore_ascii_case("disabled") {
            return None;
        }
        return Address::from_str(trimmed).ok();
    }
    match chain_id {
        1 | 10 | 56 | 137 | 8453 | 42161 => Some(alloy::primitives::address!(
            "cA11bde05977b3631167028862bE2a173976CA11"
        )),
        _ => None,
    }
}

fn decode_balance_word(raw: &[u8]) -> U256 {
    if raw.len() < 32 {
        return U256::ZERO;
    }
    let mut word = [0u8; 32];
    word.copy_from_slice(&raw[0..32]);
    U256::from_be_bytes(word)
}

fn decode_multicall_balance_results(
    tokens: &[Address],
    return_bytes: &[u8],
) -> Option<Vec<(Address, U256)>> {
    let decoded = <aggregate3Call as SolCall>::abi_decode_returns(return_bytes, true).ok()?;
    let mut out = Vec::with_capacity(tokens.len());
    for (token, result) in tokens.iter().zip(decoded.returnData.into_iter()) {
        let balance = if result.success {
            decode_balance_word(result.returnData.as_ref())
        } else {
            U256::ZERO
        };
        out.push((*token, balance));
    }
    Some(out)
}

fn high_value_cache() -> &'static DashMap<Address, (bool, u64)> {
    static CACHE: OnceLock<DashMap<Address, (bool, u64)>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn structural_hubris_cache() -> &'static DashMap<Address, u64> {
    static CACHE: OnceLock<DashMap<Address, u64>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn target_capital_estimate_cache() -> &'static DashMap<Address, (U256, u64)> {
    static CACHE: OnceLock<DashMap<Address, (U256, u64)>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn trim_timestamped_address_cache<T>(
    cache: &'static DashMap<Address, T>,
    max_entries: usize,
    prune_budget: usize,
    should_prune: impl Fn(&T) -> bool,
) {
    if cache.len() <= max_entries {
        return;
    }
    let mut keys = Vec::new();
    for entry in cache.iter().take(prune_budget) {
        if should_prune(entry.value()) {
            keys.push(*entry.key());
        }
    }
    for key in keys {
        cache.remove(&key);
    }
}

fn remember_structural_hubris(address: Address, now: u64) {
    let cache = structural_hubris_cache();
    cache.insert(address, now);
    trim_timestamped_address_cache(cache, HIGH_VALUE_CACHE_MAX_ENTRIES, 2_048, |ts| {
        now.saturating_sub(*ts) > HIGH_VALUE_CACHE_TTL_MS
    });
}

fn recent_structural_hubris_hit(address: Address, now: u64) -> bool {
    let cache = structural_hubris_cache();
    if let Some(entry) = cache.get(&address) {
        let ts = *entry.value();
        if now.saturating_sub(ts) <= HIGH_VALUE_CACHE_TTL_MS {
            return true;
        }
    }
    cache.remove(&address);
    false
}

fn record_high_value_cache_decision(address: Address, decision: bool, now: u64) {
    let cache = high_value_cache();
    cache.insert(address, (decision, now));
    trim_timestamped_address_cache(cache, HIGH_VALUE_CACHE_MAX_ENTRIES, 2_048, |(_, ts)| {
        now.saturating_sub(*ts) > HIGH_VALUE_CACHE_TTL_MS
    });
}

fn high_value_cache_decision(address: Address, now: u64) -> Option<bool> {
    let cache = high_value_cache();
    if let Some(entry) = cache.get(&address) {
        let (cached, ts) = *entry.value();
        if now.saturating_sub(ts) <= HIGH_VALUE_CACHE_TTL_MS {
            return Some(cached);
        }
    }
    cache.remove(&address);
    None
}

/// Best-effort TVL proxy cache (ETH-wei) for recent targets.
/// Used by runtime risk policy to decide whether to ignore generic global RPC cooldowns.
pub fn record_target_capital_estimate(address: Address, tvl_eth_wei: U256) {
    let now = now_ms();
    let cache = target_capital_estimate_cache();
    cache.insert(address, (tvl_eth_wei, now));
    trim_timestamped_address_cache(
        cache,
        CAPITAL_ESTIMATE_CACHE_MAX_ENTRIES,
        2_048,
        |(_, ts)| now.saturating_sub(*ts) > CAPITAL_ESTIMATE_CACHE_TTL_MS,
    );
}

pub fn target_capital_estimate_eth_wei(address: Address) -> Option<U256> {
    let now = now_ms();
    let cache = target_capital_estimate_cache();
    if let Some(entry) = cache.get(&address) {
        let (value, ts) = *entry.value();
        if now.saturating_sub(ts) <= CAPITAL_ESTIMATE_CACHE_TTL_MS {
            return Some(value);
        }
    }
    cache.remove(&address);
    None
}

fn is_rate_limited_error(msg: &str) -> bool {
    let rate_limited = crate::utils::rpc::is_rate_limited_rpc_error(msg);
    if rate_limited {
        crate::utils::rpc::signal_global_rate_limited_rpc_error();
    }
    rate_limited
}

fn has_selector(selectors: &[Bytes], needle: [u8; 4]) -> bool {
    selectors.iter().any(|s| s.as_ref() == needle)
}

fn has_structural_hubris_surface(bytecode: &Bytes) -> bool {
    static CACHE: OnceLock<DashMap<B256, bool>> = OnceLock::new();
    let cache = CACHE.get_or_init(DashMap::new);
    let code_hash = keccak256(bytecode.as_ref());
    if let Some(hit) = cache.get(&code_hash) {
        return *hit.value();
    }

    let selectors = crate::solver::heuristics::scan_for_selectors(bytecode);
    if selectors.is_empty() {
        cache.insert(code_hash, false);
        return false;
    }

    let balance_of = [0x70, 0xa0, 0x82, 0x31];
    let total_supply = [0x18, 0x16, 0x0d, 0xdd];
    let allowance = [0xdd, 0x62, 0xed, 0x3e];

    let transfer = has_selector(&selectors, crate::utils::selectors::TRANSFER);
    let transfer_from = has_selector(&selectors, crate::utils::selectors::TRANSFER_FROM);
    let approve = has_selector(&selectors, crate::utils::selectors::APPROVE);
    let balance = has_selector(&selectors, balance_of);
    let supply = has_selector(&selectors, total_supply);
    let allow = has_selector(&selectors, allowance);

    let erc20_core_count = [transfer, transfer_from, approve, balance, supply, allow]
        .into_iter()
        .filter(|present| *present)
        .count();
    let has_complete_standard_surface = erc20_core_count >= 5;
    let has_delegatecall = bytecode.as_ref().contains(&0xf4);
    let has_selfdestruct = bytecode.as_ref().contains(&0xff);
    let heavy_selector_surface = selectors.len() >= 24;

    let result = (erc20_core_count >= 2 && !has_complete_standard_surface)
        || (has_complete_standard_surface
            && (has_delegatecall || has_selfdestruct || heavy_selector_surface));
    cache.insert(code_hash, result);
    if cache.len() > STRUCTURAL_HUBRIS_SURFACE_CACHE_MAX_ENTRIES {
        let excess = cache
            .len()
            .saturating_sub(STRUCTURAL_HUBRIS_SURFACE_CACHE_MAX_ENTRIES);
        let keys = cache
            .iter()
            .take(excess.min(512))
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for key in keys {
            cache.remove(&key);
        }
    }
    result
}

pub fn default_dust_liquidity_threshold() -> U256 {
    U256::from(DEFAULT_DUST_MIN_LIQUIDITY_WEI)
}

pub fn meets_dust_liquidity(balance_wei: U256, threshold_wei: U256) -> bool {
    balance_wei >= threshold_wei
}

fn load_dust_liquidity_threshold() -> U256 {
    match std::env::var("DUST_MIN_LIQUIDITY_WEI") {
        Ok(raw) => match U256::from_str(raw.trim()) {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "[WARN] Invalid DUST_MIN_LIQUIDITY_WEI='{}'. Using default {}.",
                    raw, DEFAULT_DUST_MIN_LIQUIDITY_WEI
                );
                default_dust_liquidity_threshold()
            }
        },
        Err(_) => default_dust_liquidity_threshold(),
    }
}

fn load_backfill_enabled() -> bool {
    match std::env::var("BACKFILL_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        // Default ON: gap recovery and deployment discovery depend on backfill being active.
        // Operators can disable explicitly if their RPC budget is extremely constrained.
        Err(_) => true,
    }
}

fn load_backfill_start_offset() -> u64 {
    std::env::var("BACKFILL_START_OFFSET")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(50_000)
}

fn load_backfill_poll_ms() -> u64 {
    std::env::var("BACKFILL_POLL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(150)
}

fn load_ws_gap_replay_max_blocks_per_iteration() -> u64 {
    std::env::var("SCAN_WS_GAP_REPLAY_MAX_BLOCKS_PER_ITERATION")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1, 10_000))
        .unwrap_or(DEFAULT_WS_GAP_REPLAY_MAX_BLOCKS_PER_ITERATION)
}

fn load_ws_gap_replay_yield_ms() -> u64 {
    std::env::var("SCAN_WS_GAP_REPLAY_YIELD_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.min(2_000))
        .unwrap_or(DEFAULT_WS_GAP_REPLAY_YIELD_MS)
}

fn load_dust_sweeper_max_per_block() -> usize {
    std::env::var("SCAN_DUST_SWEEPER_MAX_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_DUST_SWEEPER_MAX_PER_BLOCK)
}

fn load_dust_candidate_set_max_per_block() -> usize {
    std::env::var("SCAN_DUST_CANDIDATE_SET_MAX_PER_BLOCK")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_DUST_CANDIDATE_SET_MAX_PER_BLOCK)
}

fn compact_error(err: impl std::fmt::Display) -> String {
    let mut raw = err.to_string();
    if let Some((prefix, _)) = raw.split_once(" text: ") {
        raw = format!("{prefix} text=<omitted>");
    }
    if let Some((prefix, _)) = raw.split_once("Stack backtrace:") {
        raw = prefix.to_string();
    }
    const MAX_LEN: usize = 320;
    let mut compact = String::with_capacity(raw.len().min(MAX_LEN.saturating_add(16)));
    let mut prev_ws = false;
    for ch in raw.chars() {
        if ch.is_whitespace() {
            if !prev_ws && !compact.is_empty() {
                compact.push(' ');
            }
            prev_ws = true;
            continue;
        }
        compact.push(ch);
        prev_ws = false;
        if compact.len() > MAX_LEN {
            break;
        }
    }
    if compact.len() <= MAX_LEN {
        compact
    } else {
        compact.truncate(MAX_LEN);
        compact.push_str("...(truncated)");
        compact
    }
}

fn looks_like_decode_incompatibility(err: &str) -> bool {
    let err_lc = err.to_ascii_lowercase();
    let opstack_extended_type = extract_unknown_tx_type_token(&err_lc)
        .map(|ty| matches!(ty.as_str(), "0x7d" | "0x7e"))
        .unwrap_or(false);
    opstack_extended_type
        || err_lc.contains("did not match any variant of untagged enum blocktransactions")
        || err_lc.contains("blocktransactions")
}

fn extract_unknown_tx_type_token(err_lc: &str) -> Option<String> {
    let markers = [
        "unknown variant `0x",
        "unknown variant '0x",
        "unknown transaction type 0x",
        "unsupported transaction type 0x",
        "typed transaction 0x",
    ];

    for marker in markers {
        if let Some(start) = err_lc.find(marker) {
            let suffix = &err_lc[start + marker.len()..];
            let mut token = String::from("0x");
            for ch in suffix.chars() {
                if ch.is_ascii_hexdigit() {
                    token.push(ch);
                } else {
                    break;
                }
            }
            if token.len() > 2 {
                return Some(token);
            }
        }
    }

    None
}

fn classify_unknown_opstack_tx_type(err: &str) -> Option<String> {
    let err_lc = err.to_ascii_lowercase();
    let has_unknown_variant =
        err_lc.contains("unknown variant") || err_lc.contains("did not match any variant");
    if !has_unknown_variant {
        return None;
    }

    if let Some(token) = extract_unknown_tx_type_token(&err_lc) {
        return Some(format!("unknown_tx_type_{}", token));
    }

    Some("unknown_tx_type_unknown".to_string())
}

fn unknown_opstack_write_sender() -> &'static std::sync::mpsc::SyncSender<UnknownOpstackDecodeWrite>
{
    static TX: OnceLock<std::sync::mpsc::SyncSender<UnknownOpstackDecodeWrite>> = OnceLock::new();
    TX.get_or_init(|| {
        let capacity = std::env::var("SCAN_UNKNOWN_OPSTACK_WRITE_QUEUE_CAPACITY")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .map(|v| v.clamp(64, 16_384))
            .unwrap_or(DEFAULT_UNKNOWN_OPSTACK_WRITE_QUEUE_CAPACITY);
        let (tx, rx) = std::sync::mpsc::sync_channel::<UnknownOpstackDecodeWrite>(capacity);
        let _ = std::thread::Builder::new()
            .name("scanner-unknown-opstack-writer".to_string())
            .spawn(move || {
                while let Ok(write) = rx.recv() {
                    if let Err(err) = write.db.record_unknown_opstack_tx_type(
                        write.block_number,
                        write.tx_hash,
                        &write.stage,
                        &write.error_class,
                        &write.raw_error,
                    ) {
                        tracing::warn!(
                            "[SCAN] Failed to persist unknown OP-Stack decode (stage={}, block={}, tx={:?}): {}",
                            write.stage,
                            write.block_number,
                            write.tx_hash,
                            compact_error(err)
                        );
                    }
                }
            });
        tx
    })
}

fn persist_unknown_opstack_decode(
    contracts_db: Option<&ContractsDb>,
    block_number: u64,
    tx_hash: Option<alloy::primitives::B256>,
    stage: &str,
    raw_error: &str,
) {
    let Some(error_class) = classify_unknown_opstack_tx_type(raw_error) else {
        return;
    };
    let Some(db) = contracts_db else {
        return;
    };
    let write = UnknownOpstackDecodeWrite {
        db: db.clone(),
        block_number,
        tx_hash,
        stage: stage.to_string(),
        error_class,
        raw_error: raw_error.to_string(),
    };
    match unknown_opstack_write_sender().try_send(write) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            warn_scan_throttled(
                "[SCAN] Unknown OP-Stack decode writer queue full; dropping telemetry sample."
                    .to_string(),
            );
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            warn_scan_throttled(
                "[SCAN] Unknown OP-Stack decode writer unavailable; dropping telemetry sample."
                    .to_string(),
            );
        }
    }
}

fn looks_like_provider_pressure(err: &str) -> bool {
    let err_lc = err.to_ascii_lowercase();
    err_lc.contains("timed out")
        || err_lc.contains("timeout")
        || err_lc.contains("429")
        || err_lc.contains("rate limit")
}

async fn contract_meets_dust_liquidity<P, T>(
    provider: &P,
    address: Address,
    threshold_wei: U256,
) -> bool
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let now = now_ms();
    if recent_structural_hubris_hit(address, now) {
        return true;
    }
    let code = match tokio::time::timeout(
        Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
        provider.get_code_at(address),
    )
    .await
    {
        Ok(Ok(c)) => c,
        _ => return false,
    };
    if code.is_empty() {
        return false;
    }
    if has_structural_hubris_surface(&code) {
        remember_structural_hubris(address, now);
        return true;
    }
    match tokio::time::timeout(
        Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
        provider.get_balance(address),
    )
    .await
    {
        Ok(Ok(balance)) => meets_dust_liquidity(balance, threshold_wei),
        Err(_) => false,
        Ok(Err(_)) => false,
    }
}

pub async fn contract_meets_high_value_tvl<P, T>(
    provider: &P,
    address: Address,
    chain_id: u64,
    threshold_wei: U256,
) -> bool
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if threshold_wei == U256::ZERO {
        return true;
    }

    let mut uncertain_due_to_provider_pressure = false;
    let code = match tokio::time::timeout(
        Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
        provider.get_code_at(address),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(err)) => {
            let err_msg = err.to_string();
            uncertain_due_to_provider_pressure =
                looks_like_provider_pressure(&err_msg) || is_rate_limited_error(&err_msg);
            if uncertain_due_to_provider_pressure && allow_high_value_unknown_admission(address) {
                warn_scan_throttled(format!(
                    "[SCAN] High-value admission uncertainty override (code fetch failed) for {:?}.",
                    address
                ));
                return true;
            }
            return false;
        }
        Err(_) => {
            if allow_high_value_unknown_admission(address) {
                warn_scan_throttled(format!(
                    "[SCAN] High-value admission uncertainty override (code fetch timeout) for {:?}.",
                    address
                ));
                return true;
            }
            return false;
        }
    };
    if code.is_empty() {
        return false;
    }

    let now = now_ms();
    if let Some(cached) = high_value_cache_decision(address, now) {
        return cached;
    }

    let mut total_eth_wei = match tokio::time::timeout(
        Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
        provider.get_balance(address),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(err)) => {
            uncertain_due_to_provider_pressure |= looks_like_provider_pressure(&err.to_string());
            U256::ZERO
        }
        Err(_) => {
            uncertain_due_to_provider_pressure = true;
            U256::ZERO
        }
    };
    record_target_capital_estimate(address, total_eth_wei);
    if total_eth_wei >= threshold_wei {
        record_high_value_cache_decision(address, true, now_ms());
        return true;
    }

    let calldata = balance_of_calldata(address);
    let tokens = top_priority_tokens(chain_id);
    if !tokens.is_empty() {
        let chain_config = crate::config::chains::ChainConfig::get(chain_id);
        let stable_price_eth_wei = stable_token_eth_price_wei();
        let price_overrides = scanner_price_overrides_eth_wei();
        let decimal_overrides = scanner_decimal_overrides();
        let calls = tokens
            .iter()
            .map(|token| Multicall3Call {
                target: *token,
                allowFailure: true,
                callData: calldata.clone(),
            })
            .collect::<Vec<_>>();
        let multicall_result = if let Some(multicall_addr) = multicall3_address_for_chain(chain_id)
        {
            let req = alloy::rpc::types::TransactionRequest::default()
                .to(multicall_addr)
                .input(alloy::rpc::types::TransactionInput::new(
                    aggregate3Call { calls }.abi_encode().into(),
                ));
            tokio::time::timeout(
                Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
                provider.call(&req),
            )
            .await
            .ok()
            .and_then(|res| match res {
                Ok(raw) => Some(raw),
                Err(err) => {
                    uncertain_due_to_provider_pressure |=
                        looks_like_provider_pressure(&err.to_string())
                            || is_rate_limited_error(&err.to_string());
                    None
                }
            })
            .and_then(|raw| decode_multicall_balance_results(&tokens, raw.as_ref()))
        } else {
            None
        };
        if let Some(balances) = multicall_result {
            for (token, bal_raw) in balances {
                let Some(price_eth_wei) = token_price_eth_wei(
                    token,
                    &chain_config,
                    stable_price_eth_wei,
                    price_overrides,
                ) else {
                    continue;
                };
                let decimals = token_decimals(token, &chain_config, decimal_overrides);
                total_eth_wei = total_eth_wei.saturating_add(token_value_eth_wei(
                    bal_raw,
                    price_eth_wei,
                    decimals,
                ));
                record_target_capital_estimate(address, total_eth_wei);
                if total_eth_wei >= threshold_wei {
                    record_high_value_cache_decision(address, true, now_ms());
                    return true;
                }
            }
        } else {
            for token in tokens {
                let req = alloy::rpc::types::TransactionRequest::default()
                    .to(token)
                    .input(alloy::rpc::types::TransactionInput::new(calldata.clone()));
                let raw = match tokio::time::timeout(
                    Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
                    provider.call(&req),
                )
                .await
                {
                    Ok(Ok(raw)) => raw,
                    Ok(Err(err)) => {
                        uncertain_due_to_provider_pressure |=
                            looks_like_provider_pressure(&err.to_string())
                                || is_rate_limited_error(&err.to_string());
                        continue;
                    }
                    Err(_) => {
                        uncertain_due_to_provider_pressure = true;
                        continue;
                    }
                };
                {
                    let bal_raw = decode_balance_word(raw.as_ref());
                    let Some(price_eth_wei) = token_price_eth_wei(
                        token,
                        &chain_config,
                        stable_price_eth_wei,
                        price_overrides,
                    ) else {
                        continue;
                    };
                    let decimals = token_decimals(token, &chain_config, decimal_overrides);
                    total_eth_wei = total_eth_wei.saturating_add(token_value_eth_wei(
                        bal_raw,
                        price_eth_wei,
                        decimals,
                    ));
                    record_target_capital_estimate(address, total_eth_wei);
                    if total_eth_wei >= threshold_wei {
                        record_high_value_cache_decision(address, true, now_ms());
                        return true;
                    }
                }
            }
        }
    }

    if uncertain_due_to_provider_pressure && allow_high_value_unknown_admission(address) {
        warn_scan_throttled(format!(
            "[SCAN] High-value admission uncertainty override for {:?} under bounded budget.",
            address
        ));
        return true;
    }

    record_high_value_cache_decision(address, false, now_ms());
    record_target_capital_estimate(address, total_eth_wei);
    false
}

#[derive(Clone, Copy)]
struct PrioritizationConfig {
    chain_id: u64,
    high_value_tvl_threshold_wei: U256,
}

struct HighValueProbeBudget {
    max_target_probes: usize,
    max_deployment_probes: usize,
    target_probes_used: usize,
    deployment_probes_used: usize,
    probed_targets: HashSet<Address>,
}

impl HighValueProbeBudget {
    fn new(max_target_probes: usize, max_deployment_probes: usize) -> Self {
        Self {
            max_target_probes,
            max_deployment_probes,
            target_probes_used: 0,
            deployment_probes_used: 0,
            probed_targets: HashSet::new(),
        }
    }

    fn reserve_target_probe(&mut self, address: Address) -> bool {
        if self.probed_targets.contains(&address) {
            return false;
        }
        if self.target_probes_used >= self.max_target_probes {
            return false;
        }
        self.probed_targets.insert(address);
        self.target_probes_used = self.target_probes_used.saturating_add(1);
        true
    }

    fn reserve_deployment_probe(&mut self) -> bool {
        if self.deployment_probes_used >= self.max_deployment_probes {
            return false;
        }
        self.deployment_probes_used = self.deployment_probes_used.saturating_add(1);
        true
    }
}

#[derive(Default)]
struct IngestStats {
    matches: usize,
    deploys: usize,
    linkage_roots_probed: usize,
    linkage_targets_enqueued: usize,
}

#[derive(Default, Clone, Copy)]
struct HashModeBlockOutcome {
    fetched: bool,
    total_txs: usize,
    interesting_hits: usize,
    dust_hits: usize,
    capital_hits: usize,
    deploys: usize,
    receipt_fallback_hits: usize,
}

#[derive(Debug)]
enum CapitalProfilerProbeError {
    MulticallUnavailable,
    Call(String),
    Timeout,
    Decode(String),
}

fn advance_last_good_head(last_good_head: &Arc<AtomicU64>, block_num: u64) {
    let mut observed = last_good_head.load(Ordering::Relaxed);
    while block_num > observed {
        match last_good_head.compare_exchange_weak(
            observed,
            block_num,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(current) => observed = current,
        }
    }
}

async fn address_passes_high_value_gate<P, T>(
    provider: &Arc<P>,
    address: Address,
    prioritization: PrioritizationConfig,
    high_value_probe_budget: &mut HighValueProbeBudget,
) -> bool
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let threshold = prioritization.high_value_tvl_threshold_wei;
    if threshold == U256::ZERO {
        return true;
    }

    if let Some(cached_tvl) = target_capital_estimate_eth_wei(address) {
        return cached_tvl >= threshold;
    }
    if !high_value_probe_budget.reserve_target_probe(address) {
        return false;
    }

    contract_meets_high_value_tvl(&**provider, address, prioritization.chain_id, threshold).await
}

fn bounded_insert_dust_candidate(
    dust_candidates: &mut HashSet<Address>,
    address: Address,
    max_candidates: usize,
) {
    if address == Address::ZERO {
        return;
    }
    if dust_candidates.len() >= max_candidates && !dust_candidates.contains(&address) {
        return;
    }
    dust_candidates.insert(address);
}

#[allow(clippy::too_many_arguments)]
async fn ingest_tx_target<P, T>(
    provider: &Arc<P>,
    tx: &alloy::rpc::types::Transaction,
    sender: &TargetQueueSender,
    prioritization: PrioritizationConfig,
    high_value_probe_budget: &mut HighValueProbeBudget,
    max_dust_candidates: usize,
    queued_targets: &mut HashSet<Address>,
    dust_candidates: &mut HashSet<Address>,
    stats: &mut IngestStats,
) where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let to = tx.to();
    let input = tx.input();

    if to.is_none() {
        stats.deploys += 1;
        // High-value-only acquisition: keep a very small budget for deployment probes.
        if prioritization.high_value_tvl_threshold_wei == U256::ZERO
            || high_value_probe_budget.reserve_deployment_probe()
        {
            log_target_deployment(provider, tx, sender).await;
        }
        return;
    }

    if FastFilter::is_interesting(to, input) {
        if let Some(to_addr) = to {
            let high_value = address_passes_high_value_gate(
                provider,
                to_addr,
                prioritization,
                high_value_probe_budget,
            )
            .await;
            if high_value && queued_targets.insert(to_addr) {
                let prio = if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
                    TargetPriority::Normal
                } else {
                    TargetPriority::Hot
                };
                let _accepted = sender.enqueue(to_addr, prio).await;
                stats.matches += 1;
                enqueue_linked_contracts(
                    provider,
                    sender,
                    to_addr,
                    prioritization,
                    queued_targets,
                    stats,
                )
                .await;
            } else if !high_value && prioritization.high_value_tvl_threshold_wei == U256::ZERO {
                bounded_insert_dust_candidate(dust_candidates, to_addr, max_dust_candidates);
            }
        }
    } else if let Some(to_addr) = to {
        if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
            bounded_insert_dust_candidate(dust_candidates, to_addr, max_dust_candidates);
        }
    }
}

async fn enqueue_high_capital_dust_candidates<P, T>(
    provider: &Arc<P>,
    sender: &TargetQueueSender,
    prioritization: PrioritizationConfig,
    contracts_db: Option<&ContractsDb>,
    block_number: u64,
    queued_targets: &mut HashSet<Address>,
    dust_candidates: &mut HashSet<Address>,
) -> usize
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if !load_capital_profiler_enabled() {
        return 0;
    }
    if dust_candidates.is_empty() {
        return 0;
    }
    // In high-value-only mode, dust candidates are never collected; still keep this guard explicit.
    if prioritization.high_value_tvl_threshold_wei != U256::ZERO {
        return 0;
    }

    let threshold_eth_wei = load_capital_profiler_threshold_eth_wei();
    if threshold_eth_wei == U256::ZERO {
        return 0;
    }

    let tokens = capital_profiler_tokens(prioritization.chain_id);
    if tokens.is_empty() {
        return 0;
    }

    let max_addrs = load_capital_profiler_max_addrs_per_block();
    let carryover = take_capital_profiler_carryover(prioritization.chain_id, max_addrs);
    let mut candidates: Vec<Address> = Vec::with_capacity(max_addrs);
    let mut seen_candidates: HashSet<Address> = HashSet::new();
    for addr in carryover {
        if addr == Address::ZERO || queued_targets.contains(&addr) {
            continue;
        }
        if seen_candidates.insert(addr) {
            candidates.push(addr);
            if candidates.len() >= max_addrs {
                break;
            }
        }
    }
    if candidates.len() < max_addrs {
        for addr in dust_candidates.iter().copied() {
            if addr == Address::ZERO || queued_targets.contains(&addr) {
                continue;
            }
            if seen_candidates.insert(addr) {
                candidates.push(addr);
                if candidates.len() >= max_addrs {
                    break;
                }
            }
        }
    }
    if candidates.is_empty() {
        return 0;
    }

    if cfg!(test) {
        // Preserve deterministic order for tests without paying sort cost in production.
        candidates.sort();
    }
    let profiler_started_ms = now_ms();
    let profiler_budget_ms = load_capital_profiler_block_budget_ms();
    let carryover_cap = load_capital_profiler_carryover_max_addrs();
    let mut carryover_pending: Vec<Address> = Vec::new();

    let max_chunk_call_bytes = load_capital_profiler_max_chunk_calldata_bytes();
    // Conservative calldata estimate per owner: one Multicall3 call per token, each carrying
    // balanceOf(address) payload and ABI/container overhead.
    let estimated_bytes_per_owner = tokens.len().saturating_mul(160).max(160);
    let max_owners_by_bytes = max_chunk_call_bytes
        .saturating_div(estimated_bytes_per_owner)
        .max(1);
    let max_owners_by_calls =
        std::cmp::max(1usize, CAPITAL_PROFILER_MAX_MULTICALL_CALLS / tokens.len());
    let mut addrs_per_chunk = max_owners_by_calls.min(max_owners_by_bytes).max(1);
    let under_pressure = crate::utils::rpc::global_rpc_cooldown_active()
        || FULL_BLOCK_HYDRATION_FAILURE_STREAK.load(Ordering::Relaxed) >= 3;
    if under_pressure {
        addrs_per_chunk = std::cmp::max(1, addrs_per_chunk / 2);
    }
    let mut enqueued = 0usize;
    let mut remove_from_dust: Vec<Address> = Vec::new();

    let mut idx = 0usize;
    'chunks: while idx < candidates.len() {
        if now_ms().saturating_sub(profiler_started_ms) >= profiler_budget_ms {
            carryover_pending.extend_from_slice(&candidates[idx..]);
            break;
        }
        let end = idx.saturating_add(addrs_per_chunk).min(candidates.len());
        let owners = &candidates[idx..end];
        idx = end;
        let owner_balances =
            match probe_capital_profiler_owners(provider, prioritization.chain_id, owners, &tokens)
                .await
            {
                Ok(rows) => rows,
                Err(CapitalProfilerProbeError::Decode(raw_err)) => {
                    persist_capital_profiler_decode_failure(
                        contracts_db,
                        block_number,
                        prioritization.chain_id,
                        owners.len(),
                        tokens.len(),
                        &raw_err,
                    );
                    if owners.len() <= 1 {
                        continue;
                    }
                    // Fallback lane: shrink probe-set to single-owner chunks.
                    let mut owner_idx = 0usize;
                    for owner in owners.iter().copied() {
                        let owner_idx_snapshot = owner_idx;
                        owner_idx = owner_idx.saturating_add(1);
                        if now_ms().saturating_sub(profiler_started_ms) >= profiler_budget_ms {
                            carryover_pending.extend_from_slice(&owners[owner_idx_snapshot..]);
                            carryover_pending.extend_from_slice(&candidates[idx..]);
                            break 'chunks;
                        }
                        let single = [owner];
                        let single_rows = match probe_capital_profiler_owners(
                            provider,
                            prioritization.chain_id,
                            &single,
                            &tokens,
                        )
                        .await
                        {
                            Ok(rows) => rows,
                            Err(CapitalProfilerProbeError::Decode(raw_err)) => {
                                persist_capital_profiler_decode_failure(
                                    contracts_db,
                                    block_number,
                                    prioritization.chain_id,
                                    1,
                                    tokens.len(),
                                    &raw_err,
                                );
                                continue;
                            }
                            Err(CapitalProfilerProbeError::Call(err)) => {
                                is_rate_limited_error(&err);
                                continue;
                            }
                            Err(CapitalProfilerProbeError::Timeout)
                            | Err(CapitalProfilerProbeError::MulticallUnavailable) => continue,
                        };
                        for (owner_addr, balances) in single_rows {
                            let tvl_eth_wei =
                                estimate_contract_tvl_eth_wei(prioritization.chain_id, &balances);
                            record_target_capital_estimate(owner_addr, tvl_eth_wei);
                            if tvl_eth_wei >= threshold_eth_wei && queued_targets.insert(owner_addr)
                            {
                                let _accepted =
                                    sender.enqueue(owner_addr, TargetPriority::Hot).await;
                                enqueued = enqueued.saturating_add(1);
                                remove_from_dust.push(owner_addr);
                            }
                        }
                    }
                    continue;
                }
                Err(CapitalProfilerProbeError::Call(err)) => {
                    is_rate_limited_error(&err);
                    continue;
                }
                Err(CapitalProfilerProbeError::Timeout)
                | Err(CapitalProfilerProbeError::MulticallUnavailable) => continue,
            };

        for (owner, balances) in owner_balances {
            let tvl_eth_wei = estimate_contract_tvl_eth_wei(prioritization.chain_id, &balances);
            record_target_capital_estimate(owner, tvl_eth_wei);
            if tvl_eth_wei >= threshold_eth_wei && queued_targets.insert(owner) {
                let _accepted = sender.enqueue(owner, TargetPriority::Hot).await;
                enqueued = enqueued.saturating_add(1);
                remove_from_dust.push(owner);
            }
        }
    }

    if !carryover_pending.is_empty() {
        warn_scan_throttled(format!(
            "[SCAN] Capital profiler budget exhausted at block #{} after {}ms; carrying over {} candidate(s).",
            block_number,
            profiler_budget_ms,
            carryover_pending.len()
        ));
        push_capital_profiler_carryover(prioritization.chain_id, &carryover_pending, carryover_cap);
    }

    for addr in remove_from_dust {
        dust_candidates.remove(&addr);
    }

    enqueued
}

fn classify_capital_profiler_decode_error(raw_error: &str) -> &'static str {
    let err_lc = raw_error.to_ascii_lowercase();
    if err_lc.contains("buffer overrun") || err_lc.contains("overrun") {
        "abi_buffer_overrun"
    } else if err_lc.contains("input too short")
        || err_lc.contains("unexpected eof")
        || err_lc.contains("eof")
    {
        "abi_input_too_short"
    } else if err_lc.contains("offset") {
        "abi_offset_error"
    } else {
        "abi_decode_error"
    }
}

fn persist_capital_profiler_decode_failure(
    contracts_db: Option<&ContractsDb>,
    block_number: u64,
    chain_id: u64,
    owners_len: usize,
    tokens_len: usize,
    raw_error: &str,
) {
    let error_class = classify_capital_profiler_decode_error(raw_error);
    let compact = compact_error(raw_error);
    warn_scan_throttled(format!(
        "[SCAN] Capital-profiler decode failure class={} chain_id={} block={} owners={} tokens={}: {}. Fallback=smaller_chunk",
        error_class, chain_id, block_number, owners_len, tokens_len, compact
    ));
    let Some(db) = contracts_db else {
        return;
    };
    let message = format!(
        "chain_id={} owners={} tokens={} err={}",
        chain_id, owners_len, tokens_len, compact
    );
    if let Err(err) = db.record_unknown_opstack_tx_type(
        block_number,
        None,
        "capital_profiler_decode",
        error_class,
        &message,
    ) {
        warn_scan_throttled(format!(
            "[SCAN] Failed to persist capital-profiler decode failure class={} block={}: {}",
            error_class,
            block_number,
            compact_error(err)
        ));
    }
}

async fn probe_capital_profiler_owners<P, T>(
    provider: &Arc<P>,
    chain_id: u64,
    owners: &[Address],
    tokens: &[Address],
) -> std::result::Result<Vec<(Address, Vec<(Address, U256)>)>, CapitalProfilerProbeError>
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if owners.is_empty() || tokens.is_empty() {
        return Ok(Vec::new());
    }

    let Some(multicall_addr) = multicall3_address_for_chain(chain_id).or_else(multicall3_address)
    else {
        return Err(CapitalProfilerProbeError::MulticallUnavailable);
    };

    let mut calls: Vec<Multicall3Call> =
        Vec::with_capacity(owners.len().saturating_mul(tokens.len()));
    for owner in owners {
        let calldata = balance_of_calldata(*owner);
        for token in tokens {
            calls.push(Multicall3Call {
                target: *token,
                allowFailure: true,
                callData: calldata.clone(),
            });
        }
    }

    let req = alloy::rpc::types::TransactionRequest::default()
        .to(multicall_addr)
        .input(alloy::rpc::types::TransactionInput::new(
            aggregate3Call { calls }.abi_encode().into(),
        ));

    let return_bytes = match tokio::time::timeout(
        Duration::from_millis(HIGH_VALUE_MULTICALL_TIMEOUT_MS),
        provider.call(&req),
    )
    .await
    {
        Ok(Ok(raw)) => raw,
        Ok(Err(err)) => return Err(CapitalProfilerProbeError::Call(err.to_string())),
        Err(_) => return Err(CapitalProfilerProbeError::Timeout),
    };

    let decoded = <aggregate3Call as SolCall>::abi_decode_returns(return_bytes.as_ref(), true)
        .map_err(|err| CapitalProfilerProbeError::Decode(err.to_string()))?;

    let mut idx = 0usize;
    let mut out = Vec::with_capacity(owners.len());
    for owner in owners {
        let mut balances: Vec<(Address, U256)> = Vec::with_capacity(tokens.len());
        for token in tokens {
            let bal = decoded
                .returnData
                .get(idx)
                .map(|r| {
                    if r.success {
                        decode_balance_word(r.returnData.as_ref())
                    } else {
                        U256::ZERO
                    }
                })
                .unwrap_or(U256::ZERO);
            balances.push((*token, bal));
            idx = idx.saturating_add(1);
        }
        out.push((*owner, balances));
    }
    Ok(out)
}

async fn process_block_hash_mode<P, T>(
    provider: &Arc<P>,
    sender: &TargetQueueSender,
    block_num: u64,
    prioritization: PrioritizationConfig,
    dust_threshold_wei: U256,
    contracts_db: Option<&ContractsDb>,
    hydration_pool: Option<&crate::utils::rpc::HydrationProviderPool>,
) -> HashModeBlockOutcome
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let mut outcome = HashModeBlockOutcome::default();
    let mut stats = IngestStats::default();
    let mut high_value_probe_budget = HighValueProbeBudget::new(
        load_high_value_probes_per_block(),
        load_high_value_deployment_probes_per_block(),
    );
    let max_dust_candidates = load_dust_candidate_set_max_per_block();
    let mut queued_targets: HashSet<Address> = HashSet::new();
    let mut dust_candidates: HashSet<Address> = HashSet::new();
    let block_fetch_timeout_ms = load_hash_mode_block_fetch_timeout_ms();
    let tx_fetch_timeout_ms = load_hash_mode_tx_fetch_timeout_ms();
    let receipt_fetch_timeout_ms = load_hash_mode_receipt_fetch_timeout_ms();
    let block_budget_ms = load_hash_mode_block_budget_ms();
    let receipt_fallback_budget_per_block = load_hash_mode_receipt_fallback_budget_per_block();
    let mut receipt_fallback_attempts = 0usize;
    let block_started_ms = now_ms();
    let mut budget_exhausted = false;

    let block_hashes_result = if let Some(pool) = hydration_pool {
        match tokio::time::timeout(
            Duration::from_millis(block_fetch_timeout_ms),
            crate::utils::rpc::RobustRpc::get_block_by_number_hashes_with_hydration_pool_retry(
                pool, block_num, 2,
            ),
        )
        .await
        {
            Ok(Ok(v)) => Ok(Ok(v)),
            Ok(Err(e)) => Ok(Err(e)),
            Err(_) => Err(()),
        }
    } else {
        match tokio::time::timeout(
            Duration::from_millis(block_fetch_timeout_ms),
            provider.get_block_by_number(
                block_num.into(),
                alloy::rpc::types::BlockTransactionsKind::Hashes,
            ),
        )
        .await
        {
            Ok(Ok(v)) => Ok(Ok(v)),
            Ok(Err(e)) => Ok(Err(anyhow::anyhow!("{}", e))),
            Err(_) => Err(()),
        }
    };
    match block_hashes_result {
        Err(()) => {
            warn_scan_throttled(format!(
                "[SCAN] Block #{} hash fallback timed out after {}ms.",
                block_num, block_fetch_timeout_ms
            ));
        }
        Ok(Ok(Some(block_hashes))) => {
            outcome.fetched = true;
            if let Some(tx_hashes) = block_hashes.transactions.as_hashes() {
                outcome.total_txs = tx_hashes.len();
                LAST_HYDRATED_BLOCK_TX_COUNT.store(outcome.total_txs as u32, Ordering::Relaxed);
                for tx_hash in tx_hashes {
                    if now_ms().saturating_sub(block_started_ms) >= block_budget_ms {
                        budget_exhausted = true;
                        warn_scan_throttled(format!(
                            "[SCAN] Hash-mode block budget exhausted at block #{} after {}ms; stopping remaining tx hydration.",
                            block_num, block_budget_ms
                        ));
                        break;
                    }
                    let tx_lookup = {
                        let permit = match tx_by_hash_fallback_semaphore().acquire().await {
                            Ok(permit) => permit,
                            Err(_) => break,
                        };
                        let lookup = if let Some(pool) = hydration_pool {
                            tokio::time::timeout(
                                Duration::from_millis(tx_fetch_timeout_ms),
                                crate::utils::rpc::RobustRpc::get_transaction_by_hash_with_hydration_pool_retry(
                                    pool, *tx_hash, 2,
                                ),
                            )
                            .await
                        } else {
                            match tokio::time::timeout(
                                Duration::from_millis(tx_fetch_timeout_ms),
                                provider.get_transaction_by_hash(*tx_hash),
                            )
                            .await
                            {
                                Ok(Ok(v)) => Ok(Ok(v)),
                                Ok(Err(e)) => Ok(Err(anyhow::anyhow!("{}", e))),
                                Err(e) => Err(e),
                            }
                        };
                        drop(permit);
                        lookup
                    };

                    match tx_lookup {
                        Ok(Ok(Some(tx))) => {
                            ingest_tx_target(
                                provider,
                                &tx,
                                sender,
                                prioritization,
                                &mut high_value_probe_budget,
                                max_dust_candidates,
                                &mut queued_targets,
                                &mut dust_candidates,
                                &mut stats,
                            )
                            .await;
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(err)) => {
                            let raw_err = err.to_string();
                            persist_unknown_opstack_decode(
                                contracts_db,
                                block_num,
                                Some(*tx_hash),
                                "tx_by_hash",
                                &raw_err,
                            );
                            let rate_limited = is_rate_limited_error(&raw_err);
                            let pressure_err =
                                rate_limited || looks_like_provider_pressure(&raw_err);
                            tracing::debug!(
                                "[SCAN] tx hydration skipped at block #{} hash {:?}: {}",
                                block_num,
                                tx_hash,
                                compact_error(&raw_err)
                            );
                            if pressure_err {
                                warn_scan_throttled(format!(
                                    "[SCAN] Skipping receipt fallback at block #{} hash {:?} due to provider pressure: {}",
                                    block_num,
                                    tx_hash,
                                    compact_error(&raw_err)
                                ));
                                continue;
                            }
                            if receipt_fallback_attempts >= receipt_fallback_budget_per_block {
                                warn_scan_throttled(format!(
                                    "[SCAN] Receipt fallback budget exhausted at block #{} (budget={}): skipping remaining tx_by_hash error escalations.",
                                    block_num,
                                    receipt_fallback_budget_per_block
                                ));
                                continue;
                            }
                            receipt_fallback_attempts = receipt_fallback_attempts.saturating_add(1);
                            let receipt_lookup = {
                                let receipt_permit =
                                    match receipt_fallback_semaphore().acquire().await {
                                        Ok(permit) => permit,
                                        Err(_) => break,
                                    };
                                let receipt = tokio::time::timeout(
                                    Duration::from_millis(receipt_fetch_timeout_ms),
                                    provider.get_transaction_receipt(*tx_hash),
                                )
                                .await;
                                drop(receipt_permit);
                                receipt
                            };
                            match receipt_lookup {
                                Ok(Ok(Some(receipt))) => {
                                    if let Some(to_addr) = receipt.to() {
                                        let allow = address_passes_high_value_gate(
                                            provider,
                                            to_addr,
                                            prioritization,
                                            &mut high_value_probe_budget,
                                        )
                                        .await;
                                        if allow && queued_targets.insert(to_addr) {
                                            let _accepted =
                                                sender.enqueue(to_addr, TargetPriority::Dust).await;
                                            outcome.receipt_fallback_hits += 1;
                                        }
                                    }
                                    if let Some(deployed_addr) = receipt.contract_address() {
                                        if prioritization.high_value_tvl_threshold_wei == U256::ZERO
                                            && queued_targets.insert(deployed_addr)
                                        {
                                            let _accepted = sender
                                                .enqueue(deployed_addr, TargetPriority::Dust)
                                                .await;
                                            outcome.receipt_fallback_hits += 1;
                                        }
                                    }
                                }
                                Ok(Ok(None)) => {}
                                Ok(Err(err)) => {
                                    let raw_err = err.to_string();
                                    persist_unknown_opstack_decode(
                                        contracts_db,
                                        block_num,
                                        Some(*tx_hash),
                                        "tx_receipt",
                                        &raw_err,
                                    );
                                    is_rate_limited_error(&raw_err);
                                }
                                Err(_) => {
                                    warn_scan_throttled(format!(
                                        "[SCAN] tx receipt lookup timed out at block #{} hash {:?} after {}ms.",
                                        block_num, tx_hash, receipt_fetch_timeout_ms
                                    ));
                                }
                            }
                            continue;
                        }
                        Err(_) => {
                            warn_scan_throttled(format!(
                                "[SCAN] tx hydration timed out at block #{} hash {:?} after {}ms.",
                                block_num, tx_hash, tx_fetch_timeout_ms
                            ));
                            continue;
                        }
                    }
                }
            }
        }
        Ok(Ok(None)) => {}
        Ok(Err(err)) => {
            let raw_err = err.to_string();
            persist_unknown_opstack_decode(contracts_db, block_num, None, "block_hashes", &raw_err);
            is_rate_limited_error(&raw_err);
            warn_scan_throttled(format!(
                "[SCAN] Block #{} hash fallback fetch failed: {}",
                block_num,
                compact_error(&raw_err)
            ));
        }
    }

    if budget_exhausted || now_ms().saturating_sub(block_started_ms) >= block_budget_ms {
        outcome.interesting_hits = stats.matches;
        outcome.deploys = stats.deploys;
        return outcome;
    }

    outcome.capital_hits = enqueue_high_capital_dust_candidates(
        provider,
        sender,
        prioritization,
        contracts_db,
        block_num,
        &mut queued_targets,
        &mut dust_candidates,
    )
    .await;

    if dust_threshold_wei != U256::ZERO {
        let max_dust_checks = load_dust_sweeper_max_per_block();
        let mut candidates: Vec<Address> = dust_candidates.into_iter().collect();
        if cfg!(test) {
            candidates.sort();
        }
        candidates.truncate(max_dust_checks);
        for candidate in candidates {
            if now_ms().saturating_sub(block_started_ms) >= block_budget_ms {
                warn_scan_throttled(format!(
                    "[SCAN] Hash-mode block budget exhausted at block #{} after {}ms; stopping dust sweep.",
                    block_num, block_budget_ms
                ));
                break;
            }
            if queued_targets.contains(&candidate) {
                continue;
            }
            if contract_meets_dust_liquidity(&**provider, candidate, dust_threshold_wei).await
                && queued_targets.insert(candidate)
            {
                let _accepted = sender.enqueue(candidate, TargetPriority::Dust).await;
                outcome.dust_hits += 1;
            }
        }
    }

    outcome.interesting_hits = stats.matches;
    outcome.deploys = stats.deploys;
    outcome
}

fn load_log_light_scan_enabled() -> bool {
    match std::env::var("SCAN_LOG_LIGHT_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn log_light_address_cooldown_ms() -> u64 {
    std::env::var("SCAN_LOG_LIGHT_ADDRESS_COOLDOWN_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|v| *v >= 250)
        .unwrap_or(DEFAULT_LOG_LIGHT_ADDRESS_COOLDOWN_MS)
}

fn log_light_max_addrs_per_min(high_value_gate_enabled: bool) -> usize {
    let default = if high_value_gate_enabled {
        DEFAULT_LOG_LIGHT_MAX_ADDRS_PER_MIN_TVL_GATED
    } else {
        DEFAULT_LOG_LIGHT_MAX_ADDRS_PER_MIN
    };
    std::env::var("SCAN_LOG_LIGHT_MAX_ADDRS_PER_MIN")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v >= 50)
        .unwrap_or(default)
}

fn log_light_high_value_probes_per_min(
    high_value_gate_enabled: bool,
    max_addrs_per_min: usize,
) -> usize {
    let default = if high_value_gate_enabled {
        DEFAULT_LOG_LIGHT_HIGH_VALUE_PROBES_PER_MIN_TVL_GATED
    } else {
        DEFAULT_LOG_LIGHT_HIGH_VALUE_PROBES_PER_MIN
    };
    let configured = std::env::var("SCAN_LOG_LIGHT_HIGH_VALUE_PROBES_PER_MIN")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default);
    configured.min(max_addrs_per_min.max(1))
}

fn light_log_topic0s() -> Vec<B256> {
    // High-signal DEX topics (minimize throughput vs ERC20 Transfer firehose).
    vec![
        keccak256("Swap(address,uint256,uint256,uint256,uint256,address)"), // UniswapV2/Sushiswap
        keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)"), // UniswapV3
    ]
}

fn build_amm_watch_filter() -> alloy::rpc::types::Filter {
    alloy::rpc::types::Filter::new()
        .event_signature(crate::solver::watch_cache::watched_event_topics())
}

fn build_light_log_filter(
    from_block: Option<u64>,
    to_block: Option<u64>,
) -> alloy::rpc::types::Filter {
    let mut filter = alloy::rpc::types::Filter::new();
    if let Some(from) = from_block {
        filter = filter.from_block(from);
    }
    if let Some(to) = to_block {
        filter = filter.to_block(to);
    }
    // Filter on event signatures (topic0).
    filter = filter.event_signature(light_log_topic0s());
    filter
}

fn should_accept_light_log_address(
    now: u64,
    addr: Address,
    cooldown_ms: u64,
    state: &mut LightLogDedupe,
) -> bool {
    state.accept(now, addr, cooldown_ms)
}

struct LightLogDedupe {
    last_seen: HashMap<Address, u64>,
    fifo: VecDeque<(Address, u64)>,
    max_entries: usize,
}

impl LightLogDedupe {
    fn new(max_entries: usize) -> Self {
        Self {
            last_seen: HashMap::new(),
            fifo: VecDeque::new(),
            max_entries: max_entries.max(1),
        }
    }

    fn accept(&mut self, now: u64, addr: Address, cooldown_ms: u64) -> bool {
        if let Some(last) = self.last_seen.get(&addr) {
            if now.saturating_sub(*last) < cooldown_ms {
                return false;
            }
        }

        self.last_seen.insert(addr, now);
        self.fifo.push_back((addr, now));
        self.prune(now, cooldown_ms);
        true
    }

    fn prune(&mut self, now: u64, cooldown_ms: u64) {
        // Expire entries older than 2x cooldown. This is amortized O(expired) without full-map scans.
        let cutoff = now.saturating_sub(cooldown_ms.saturating_mul(2));
        while let Some((addr, ts)) = self.fifo.front().copied() {
            if ts >= cutoff {
                break;
            }
            let _ = self.fifo.pop_front();
            if self.last_seen.get(&addr).copied() == Some(ts) {
                self.last_seen.remove(&addr);
            }
        }

        // Hard bound: if we still grew too large (pathological log storms), evict oldest FIFO.
        while self.last_seen.len() > self.max_entries {
            if let Some((addr, ts)) = self.fifo.pop_front() {
                if self.last_seen.get(&addr).copied() == Some(ts) {
                    self.last_seen.remove(&addr);
                }
            } else {
                break;
            }
        }
    }
}

async fn log_light_address_passes_high_value_gate<P, T>(
    provider: &Arc<P>,
    addr: Address,
    prioritization: PrioritizationConfig,
    probes_in_window: &mut usize,
    max_probes_per_min: usize,
) -> bool
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
        return true;
    }
    let threshold = prioritization.high_value_tvl_threshold_wei;
    if target_capital_estimate_eth_wei(addr)
        .map(|v| v >= threshold)
        .unwrap_or(false)
    {
        return true;
    }
    if *probes_in_window >= max_probes_per_min {
        return false;
    }
    *probes_in_window = probes_in_window.saturating_add(1);
    contract_meets_high_value_tvl(provider.as_ref(), addr, prioritization.chain_id, threshold).await
}

#[allow(clippy::too_many_arguments)]
async fn replay_ws_gap_range<P, T>(
    provider: &Arc<P>,
    sender: &TargetQueueSender,
    last_good_head: &Arc<AtomicU64>,
    reconnect_head: u64,
    prioritization: PrioritizationConfig,
    dust_threshold_wei: U256,
    contracts_db: Option<&ContractsDb>,
    hydration_pool: Option<&crate::utils::rpc::HydrationProviderPool>,
) where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let last_good = last_good_head.load(Ordering::Relaxed);
    if last_good == 0 || reconnect_head <= last_good.saturating_add(1) {
        return;
    }

    let start_block = last_good.saturating_add(1);
    let end_block = reconnect_head;
    let max_replay = load_ws_gap_replay_max_blocks_per_iteration();
    let capped_end = end_block.min(start_block.saturating_add(max_replay.saturating_sub(1)));
    tracing::warn!(
        "[SCAN] WS gap detected (last_good={} reconnect_head={}); replaying blocks [{}..={}].",
        last_good,
        reconnect_head,
        start_block,
        capped_end
    );

    let mut recovered = true;
    let mut replayed = 0u64;
    let mut queued_total = 0usize;
    let yield_ms = load_ws_gap_replay_yield_ms();

    for block_num in start_block..=capped_end {
        let outcome = process_block_hash_mode(
            provider,
            sender,
            block_num,
            prioritization,
            dust_threshold_wei,
            contracts_db,
            hydration_pool,
        )
        .await;

        recovered &= outcome.fetched;
        replayed = replayed.saturating_add(1);
        queued_total = queued_total
            .saturating_add(outcome.interesting_hits)
            .saturating_add(outcome.dust_hits)
            .saturating_add(outcome.capital_hits)
            .saturating_add(outcome.receipt_fallback_hits);
        advance_last_good_head(last_good_head, block_num);
        if replayed.is_multiple_of(8) {
            tokio::task::yield_now().await;
            if yield_ms > 0 {
                tokio::time::sleep(Duration::from_millis(yield_ms)).await;
            }
        }
    }

    if let Some(db) = contracts_db {
        if let Err(err) =
            db.record_scanner_gap_replay(start_block, capped_end, recovered, reconnect_head)
        {
            warn_scan_throttled(format!(
                "[SCAN] Failed to persist ws-gap replay [{}..={}]: {}",
                start_block,
                capped_end,
                compact_error(err)
            ));
        }
    }

    tracing::info!(
        "[SCAN] WS gap replay complete: replayed={} blocks queued={} recovered={} remaining_gap_blocks={}.",
        replayed,
        queued_total,
        recovered,
        end_block.saturating_sub(capped_end)
    );
}

async fn replay_ws_gap_range_logs<P, T>(
    provider: &Arc<P>,
    sender: &TargetQueueSender,
    last_good_head: &Arc<AtomicU64>,
    reconnect_head: u64,
    prioritization: PrioritizationConfig,
) where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    let last_good = last_good_head.load(Ordering::Relaxed);
    if last_good == 0 || reconnect_head <= last_good.saturating_add(1) {
        return;
    }

    let start_block = last_good.saturating_add(1);
    let end_block = reconnect_head;
    tracing::warn!(
        "[SCAN] WS gap detected (last_good={} reconnect_head={}); replaying logs [{}..={}].",
        last_good,
        reconnect_head,
        start_block,
        end_block
    );

    let cooldown_ms = log_light_address_cooldown_ms();
    let high_value_gate_enabled = prioritization.high_value_tvl_threshold_wei != U256::ZERO;
    let max_addrs_per_min = log_light_max_addrs_per_min(high_value_gate_enabled);
    let max_high_value_probes_per_min =
        log_light_high_value_probes_per_min(high_value_gate_enabled, max_addrs_per_min);
    let now = now_ms();
    let mut dedupe = LightLogDedupe::new(25_000);
    let mut queued = 0usize;
    let mut probes_in_window = 0usize;

    let filter = build_light_log_filter(Some(start_block), Some(end_block));
    match provider.get_logs(&filter).await {
        Ok(logs) => {
            for log in logs {
                let _ = crate::solver::watch_cache::ingest_amm_log(&log);
                let addr = log.address();
                if should_accept_light_log_address(now, addr, cooldown_ms, &mut dedupe) {
                    let allow = log_light_address_passes_high_value_gate(
                        provider,
                        addr,
                        prioritization,
                        &mut probes_in_window,
                        max_high_value_probes_per_min,
                    )
                    .await;
                    if !allow {
                        continue;
                    }
                    let _accepted = sender.enqueue(addr, TargetPriority::Normal).await;
                    queued = queued.saturating_add(1);
                    if queued >= max_addrs_per_min {
                        break;
                    }
                }
            }
        }
        Err(err) => {
            warn_scan_throttled(format!(
                "[SCAN] Log-based gap replay failed [{}..={}]: {}",
                start_block,
                end_block,
                compact_error(err)
            ));
        }
    }

    advance_last_good_head(last_good_head, reconnect_head);
    tracing::info!(
        "[SCAN] Log gap replay complete: queued={} blocks=[{}..={}].",
        queued,
        start_block,
        end_block
    );
}

async fn maybe_enqueue_backfill_target<P, T>(
    provider: &Arc<P>,
    sender: &TargetQueueSender,
    queued_targets: &mut HashSet<Address>,
    address: Address,
    prioritization: PrioritizationConfig,
) -> bool
where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    if queued_targets.contains(&address) {
        return false;
    }
    let allow = if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
        true
    } else {
        contract_meets_high_value_tvl(
            &**provider,
            address,
            prioritization.chain_id,
            prioritization.high_value_tvl_threshold_wei,
        )
        .await
    };
    if !allow {
        return false;
    }
    if queued_targets.insert(address) {
        let _accepted = sender.enqueue(address, TargetPriority::Dust).await;
        return true;
    }
    false
}

// FAST FILTER: Stateless & Heuristic
// Purpose: Reject 99% of traffic before expensive parsing or logic.
struct FastFilter;

impl FastFilter {
    #[inline(always)]
    fn is_interesting(to: Option<Address>, input: &Bytes) -> bool {
        // 1. Must be a contract call (to != None)
        let _to_addr = match to {
            Some(a) => a,
            None => return false, // Deployment handled separately
        };

        // 2. Input Length Check (at least selector)
        if input.len() < 4 {
            return false;
        }

        // 3. Hot Selector Check (Manual Bloom)
        // 3. Hot Selector Check (Manual Bloom)
        let selector = &input[0..4];
        match selector {
            // ERC20 / 721
            v if v == crate::utils::selectors::TRANSFER => true,
            v if v == crate::utils::selectors::TRANSFER_FROM => true,
            v if v == crate::utils::selectors::APPROVE => true,
            // Uniswap / AMM
            v if v == crate::utils::selectors::SWAP_EXACT_TOKENS_FOR_TOKENS => true,
            v if v == crate::utils::selectors::SWAP_EXACT_TOKENS_FOR_ETH => true,
            v if v == crate::utils::selectors::SWAP_EXACT_ETH_FOR_TOKENS => true,
            v if v == crate::utils::selectors::SWAP_EXACT_TOKENS_FOR_TOKENS_SUPPORTING_FEE => true,
            // Lending / Vaults
            v if v == crate::utils::selectors::FLASH_LOAN => true,
            v if v == crate::utils::selectors::WITHDRAW => true,
            v if v == crate::utils::selectors::CLAIM => true,
            v if v == crate::utils::selectors::REDEEM => true,
            // General Interaction
            _ => fast_filter_allow_all_enabled(),
        }
    }
}

pub async fn start_scanner(
    ws_url: &str,
    target_sender: TargetQueueSender,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    last_good_head: Arc<AtomicU64>,
    contracts_db: Option<ContractsDb>,
    hydration_pool: Arc<crate::utils::rpc::HydrationProviderPool>,
) -> Result<()> {
    // Connect to WebSocket with timeout to avoid hanging indefinitely when
    // the endpoint doesn't support eth_subscribe or is unresponsive.
    let ws_connect_timeout_ms = load_ws_connect_timeout_ms();
    let provider = match tokio::time::timeout(
        Duration::from_millis(ws_connect_timeout_ms),
        ProviderBuilder::new().on_ws(alloy::transports::ws::WsConnect::new(ws_url)),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(err)) => {
            return Err(anyhow::anyhow!(
                "[SCAN] WS connection to {} failed: {}",
                ws_url,
                compact_error(err)
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "[SCAN] WS connection to {} timed out after {}ms. \
                 The endpoint may not support eth_subscribe.",
                ws_url,
                ws_connect_timeout_ms
            ));
        }
    };
    let provider = Arc::new(provider);

    tracing::info!("Connected to WS: {}", ws_url);
    let log_light_enabled = load_log_light_scan_enabled();
    if log_light_enabled {
        // In light mode, rely primarily on log subscriptions; skip expensive full-block hydration.
        FULL_BLOCK_HYDRATION_ENABLED.store(false, Ordering::Relaxed);
        tracing::info!("[SCAN] Log-light detection enabled (SCAN_LOG_LIGHT_ENABLED=1).");
    }
    let dust_threshold_wei_raw = load_dust_liquidity_threshold();
    let hydration_base_timeout_ms = load_hydration_base_timeout_ms();
    let skip_on_congestion = load_skip_on_congestion();
    let high_value_tvl_threshold_wei = load_high_value_tvl_threshold();
    let chain_id_timeout_ms = load_chain_id_timeout_ms();
    let chain_id = match tokio::time::timeout(
        Duration::from_millis(chain_id_timeout_ms),
        provider.get_chain_id(),
    )
    .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(err)) => {
            return Err(anyhow::anyhow!(
                "[SCAN] Failed to fetch chain id: {}",
                compact_error(err)
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "[SCAN] Timed out fetching chain id after {}ms.",
                chain_id_timeout_ms
            ));
        }
    };

    // Phase 17: Zero-latency sequencer feed via pending-tx websocket ingestion.
    // This runs alongside the canonical block subscription; it is purely a pre-block hint.
    let shutdown_rx_pending = shutdown_rx.resubscribe();
    spawn_sequencer_ws_ingestion_task(
        provider.clone(),
        target_sender.clone(),
        shutdown_rx_pending,
        chain_id,
        high_value_tvl_threshold_wei,
    )
    .await;

    let dust_threshold_wei = if high_value_tvl_threshold_wei != U256::ZERO {
        tracing::info!(
            "[SCAN] High-value TVL gate enabled: threshold={} ETH-wei (use HIGH_VALUE_TVL_USD=0 to disable).",
            high_value_tvl_threshold_wei
        );
        tracing::info!("[SCAN] Dust sweeper disabled (high-value-only acquisition mode).");
        U256::ZERO
    } else {
        tracing::info!(
            "[SCAN] High-value TVL gate disabled (set HIGH_VALUE_TVL_USD or HIGH_VALUE_TVL_WEI to enable)."
        );
        tracing::info!(
            "[SCAN] Dust sweeper active: contract ETH liquidity threshold = {} wei",
            dust_threshold_wei_raw
        );
        dust_threshold_wei_raw
    };

    let head_timeout_ms = load_head_fetch_timeout_ms();
    let reconnect_head = match tokio::time::timeout(
        Duration::from_millis(head_timeout_ms),
        provider.get_block_number(),
    )
    .await
    {
        Ok(Ok(head)) => head,
        Ok(Err(err)) => {
            return Err(anyhow::anyhow!(
                "[SCAN] Failed to fetch reconnect head: {}",
                compact_error(err)
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "[SCAN] Timed out fetching reconnect head after {}ms.",
                head_timeout_ms
            ));
        }
    };
    if log_light_enabled {
        replay_ws_gap_range_logs(
            &provider,
            &target_sender,
            &last_good_head,
            reconnect_head,
            PrioritizationConfig {
                chain_id,
                high_value_tvl_threshold_wei,
            },
        )
        .await;
    } else {
        // DEEP AUDIT MODE: Bypass ingestion if we are in siege mode.
        // This logic replaces the standard "listen and react" loop with a "load and hammer" loop.
        let audit_mode = std::env::var("SCAN_AUDIT_MODE")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(true); // Default to TRUE for this pivot

        if audit_mode {
            tracing::warn!("[SCAN] 🚨 DEEP AUDIT MODE ACTIVATED 🚨");
            tracing::warn!("[SCAN] Ingestion DISABLED. Network traffic minimized.");
            tracing::warn!("[SCAN] Focusing exclusively on high-value targets from DB.");

            // Spawn the Audit Loop
            let db_clone = contracts_db.clone();
            let sender_clone = target_sender.clone();
            tokio::spawn(async move {
                let db = match db_clone {
                    Some(d) => d,
                    None => {
                        tracing::error!("[SCAN] Audit mode requires DB! Aborting loop.");
                        return;
                    }
                };

                loop {
                    tracing::info!("[SCAN] Audit Loop: Fetching high-priority targets...");
                    match db.get_all_high_priority_targets() {
                        Ok(targets) => {
                            if targets.is_empty() {
                                tracing::warn!("[SCAN] No targets found in DB. Sleeping 10s.");
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                continue;
                            }

                            tracing::info!("[SCAN] Loaded {} targets. Hammering...", targets.len());
                            for target in targets {
                                // Enqueue as HOT to bypass normal queues.
                                let accepted =
                                    sender_clone.enqueue(target, TargetPriority::Hot).await;
                                if !accepted {
                                    tracing::warn!(
                                    "[SCAN] Target queue rejected high-priority target {} (queue full).",
                                    target
                                );
                                }
                                // Small delay to prevent channel overflow, but aggressive enough
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                        Err(e) => {
                            tracing::error!("[SCAN] DB Fetch failed: {}", e);
                        }
                    }

                    tracing::info!("[SCAN] Cycle complete. Sleeping 5s before re-scan.");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
        } else {
            // LEGACY INGESTION LOGIC (Only runs if Audit Mode is explicitly OFF)
            replay_ws_gap_range(
                &provider,
                &target_sender,
                &last_good_head,
                reconnect_head,
                PrioritizationConfig {
                    chain_id,
                    high_value_tvl_threshold_wei,
                },
                dust_threshold_wei,
                contracts_db.as_ref(),
                Some(&hydration_pool),
            )
            .await;
        }
    }

    let chain_name = crate::config::chains::ChainConfig::get(chain_id).name;
    tracing::info!(
        "[*] Listening for new blocks on {} (Parallel Workers)...",
        chain_name
    );

    // CONCURRENCY CONTROL
    // We don't want to spawn infinite tasks if the node floods us.
    // 50 concurrent block processors is plenty.
    let _semaphore = Arc::new(Semaphore::new(load_block_worker_concurrency()));
    let ws_subscribe_timeout_ms = load_ws_subscribe_timeout_ms();
    let mut primary_stream = {
        let sub = match tokio::time::timeout(
            Duration::from_millis(ws_subscribe_timeout_ms),
            provider.subscribe_blocks(),
        )
        .await
        {
            Ok(Ok(sub)) => sub,
            Ok(Err(err)) => {
                return Err(anyhow::anyhow!(
                    "[SCAN] subscribe_blocks failed: {}. \
                     The endpoint may not support eth_subscribe.",
                    compact_error(err)
                ));
            }
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "[SCAN] subscribe_blocks timed out after {}ms. \
                     The endpoint may not support eth_subscribe.",
                    ws_subscribe_timeout_ms
                ));
            }
        };
        Some(sub.into_stream())
    };
    let mut raced_head_rx: Option<tokio::sync::mpsc::Receiver<HeadRaceEvent>> = None;

    let race_urls = load_public_ws_race_urls(ws_url);
    if race_urls.len() > 1 {
        let channel_capacity = load_public_ws_race_channel_capacity();
        let (head_tx, head_rx) = tokio::sync::mpsc::channel::<HeadRaceEvent>(channel_capacity);
        let mut active_feeds = 0usize;

        {
            let provider_heads = provider.clone();
            let tx_heads = head_tx.clone();
            let source_label = "primary".to_string();
            tokio::spawn(async move {
                let sub = match provider_heads.subscribe_blocks().await {
                    Ok(sub) => sub,
                    Err(err) => {
                        warn_scan_throttled(format!(
                            "[SCAN] Primary head feed subscription failed: {}",
                            compact_error(err)
                        ));
                        return;
                    }
                };
                let mut stream = sub.into_stream();
                while let Some(block) = stream.next().await {
                    if tx_heads
                        .send(HeadRaceEvent {
                            number: block.number,
                            hash: block.hash,
                            source: source_label.clone(),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            active_feeds = active_feeds.saturating_add(1);
        }

        for candidate in race_urls.into_iter().filter(|u| u != ws_url) {
            let connect_result = tokio::time::timeout(
                Duration::from_millis(ws_connect_timeout_ms),
                ProviderBuilder::new()
                    .on_ws(alloy::transports::ws::WsConnect::new(candidate.clone())),
            )
            .await;
            match connect_result {
                Ok(Ok(feed_provider)) => {
                    let tx_heads = head_tx.clone();
                    let sub_timeout = Duration::from_millis(ws_subscribe_timeout_ms);
                    tokio::spawn(async move {
                        let sub = match tokio::time::timeout(
                            sub_timeout,
                            feed_provider.subscribe_blocks(),
                        )
                        .await
                        {
                            Ok(Ok(sub)) => sub,
                            Ok(Err(err)) => {
                                warn_scan_throttled(format!(
                                    "[SCAN] Public head feed subscription failed ({}): {}",
                                    candidate,
                                    compact_error(err)
                                ));
                                return;
                            }
                            Err(_) => {
                                warn_scan_throttled(format!(
                                    "[SCAN] Public head feed subscribe_blocks timed out ({})",
                                    candidate,
                                ));
                                return;
                            }
                        };
                        let mut stream = sub.into_stream();
                        while let Some(block) = stream.next().await {
                            if tx_heads
                                .send(HeadRaceEvent {
                                    number: block.number,
                                    hash: block.hash,
                                    source: candidate.clone(),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    active_feeds = active_feeds.saturating_add(1);
                }
                Ok(Err(err)) => {
                    warn_scan_throttled(format!(
                        "[SCAN] Failed to connect public head feed {}: {}",
                        candidate,
                        compact_error(err)
                    ));
                }
                Err(_) => {
                    warn_scan_throttled(format!(
                        "[SCAN] WS connect timed out for public head feed {}",
                        candidate,
                    ));
                }
            }
        }

        if active_feeds > 1 {
            raced_head_rx = Some(head_rx);
            primary_stream = None;
            tracing::info!(
                "[SCAN] Multi-stream public head racing enabled with {} feeds (SCAN_PUBLIC_WS_RACE_URLS).",
                active_feeds
            );
        } else {
            tracing::info!(
                "[SCAN] Multi-stream public head racing requested but no additional feeds connected; using primary stream."
            );
        }
    }

    if log_light_enabled {
        let provider_logs = provider.clone();
        let sender_logs = target_sender.clone();
        let cooldown_ms = log_light_address_cooldown_ms();
        let high_value_gate_enabled = high_value_tvl_threshold_wei != U256::ZERO;
        let max_addrs_per_min = log_light_max_addrs_per_min(high_value_gate_enabled);
        let prioritization = PrioritizationConfig {
            chain_id,
            high_value_tvl_threshold_wei,
        };
        tokio::spawn(async move {
            let filter = build_light_log_filter(None, None);
            let sub = match provider_logs.subscribe_logs(&filter).await {
                Ok(sub) => sub,
                Err(err) => {
                    warn_scan_throttled(format!(
                        "[SCAN] Failed to subscribe to logs (light mode): {}",
                        compact_error(err)
                    ));
                    return;
                }
            };

            let mut stream = sub.into_stream();
            let mut dedupe = LightLogDedupe::new(25_000);
            let mut window_start = now_ms();
            let mut queued_in_window = 0usize;
            let mut probe_window_start = window_start;
            let mut probes_in_window = 0usize;
            let max_high_value_probes_per_min =
                log_light_high_value_probes_per_min(high_value_gate_enabled, max_addrs_per_min);

            while let Some(log) = stream.next().await {
                let _ = crate::solver::watch_cache::ingest_amm_log(&log);
                let now = now_ms();
                if now.saturating_sub(window_start) >= 60_000 {
                    window_start = now;
                    queued_in_window = 0;
                }
                if now.saturating_sub(probe_window_start) >= 60_000 {
                    probe_window_start = now;
                    probes_in_window = 0;
                }
                if queued_in_window >= max_addrs_per_min {
                    continue;
                }

                let addr = log.address();
                if !should_accept_light_log_address(now, addr, cooldown_ms, &mut dedupe) {
                    continue;
                }

                let allow = log_light_address_passes_high_value_gate(
                    &provider_logs,
                    addr,
                    prioritization,
                    &mut probes_in_window,
                    max_high_value_probes_per_min,
                )
                .await;
                if !allow {
                    continue;
                }

                let _accepted = sender_logs.enqueue(addr, TargetPriority::Normal).await;
                queued_in_window = queued_in_window.saturating_add(1);
            }
        });
    }

    {
        let provider_amm = provider.clone();
        tokio::spawn(async move {
            let filter = build_amm_watch_filter();
            let sub = match provider_amm.subscribe_logs(&filter).await {
                Ok(sub) => sub,
                Err(err) => {
                    warn_scan_throttled(format!(
                        "[SCAN] Failed to subscribe to AMM watch cache logs: {}",
                        compact_error(err)
                    ));
                    return;
                }
            };

            let mut stream = sub.into_stream();
            while let Some(log) = stream.next().await {
                let _ = crate::solver::watch_cache::ingest_amm_log(&log);
            }
        });
    }

    let mut last_dispatched_block = reconnect_head;
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("[SCAN] Shutdown signal received. Stopping scanner...");
                break;
            }
            maybe_head = async {
                if let Some(rx) = raced_head_rx.as_mut() {
                    rx.recv().await
                } else if let Some(stream) = primary_stream.as_mut() {
                    stream.next().await.map(|block| HeadRaceEvent {
                        number: block.number,
                        hash: block.hash,
                        source: "primary".to_string(),
                    })
                } else {
                    None
                }
            } => {
                let Some(head_event) = maybe_head else {
                    return Err(anyhow::anyhow!(
                        "scanner websocket stream ended unexpectedly"
                    ));
                };
                let block_num = head_event.number;
                let block_hash = head_event.hash;
                let head_source = head_event.source;
                if block_num <= last_dispatched_block {
                    tracing::debug!(
                        "[SCAN] Ignoring duplicate/stale head #{} from {} (last_dispatched={}).",
                        block_num,
                        head_source,
                        last_dispatched_block
                    );
                    continue;
                }
                last_dispatched_block = block_num;

                if log_light_enabled {
                    // In light mode, block headers are used only for head-tracking and liveness.
                    advance_last_good_head(&last_good_head, block_num);
                    continue;
                }

                let provider_clone = provider.clone();
                let hydration_pool_clone = hydration_pool.clone();
                let sender_clone = target_sender.clone();
                let permit = match _semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn_scan_throttled(format!(
                            "[SCAN] Worker pool saturated at block #{}; skipping immediate block worker dispatch.",
                            block_num
                        ));
                        continue;
                    }
                };
                let last_good_head_block = last_good_head.clone();
                let dust_threshold_wei_block = dust_threshold_wei;
                let hydration_base_timeout_ms_block = hydration_base_timeout_ms;
                let skip_on_congestion_block = skip_on_congestion;
                let high_value_tvl_threshold_wei_block = high_value_tvl_threshold_wei;
                let chain_id_block = chain_id;
                let contracts_db_block = contracts_db.clone();

                // SPORN: Parallel Dispatch
                // We do NOT await here. We spawn and move on to the next block header.
                tokio::spawn(async move {
                    let _permit = permit;

                    let now = now_ms();
                    let retry_ms = load_full_block_hydration_retry_ms();
                    if !FULL_BLOCK_HYDRATION_ENABLED.load(Ordering::Relaxed) && retry_ms > 0 {
                        let until = FULL_BLOCK_HYDRATION_DISABLED_UNTIL_MS.load(Ordering::Relaxed);
                        if until > 0 && now >= until {
                            FULL_BLOCK_HYDRATION_ENABLED.store(true, Ordering::Relaxed);
                            FULL_BLOCK_HYDRATION_FAILURE_STREAK.store(0, Ordering::Relaxed);
                            FULL_BLOCK_HYDRATION_DISABLED_UNTIL_MS.store(0, Ordering::Relaxed);
                            tracing::info!("[SCAN] Retrying full-block hydration after decode disable cooldown.");
                        }
                    }

                    let pressure_streak = FULL_BLOCK_HYDRATION_FAILURE_STREAK.load(Ordering::Relaxed);
                    let should_try_full_hydration = FULL_BLOCK_HYDRATION_ENABLED.load(Ordering::Relaxed)
                        && !(skip_on_congestion_block && pressure_streak >= 4);
                    if !should_try_full_hydration && skip_on_congestion_block && pressure_streak >= 4 {
                        warn_scan_throttled(format!(
                            "[SCAN] Congestion guard active at block #{} (streak={}). Skipping full hydration to preserve RPC quota.",
                            block_num,
                            pressure_streak
                        ));
                    }

                    let block_full = if should_try_full_hydration {
                        let hydration_timeout_ms =
                            adaptive_hydration_timeout_ms(hydration_base_timeout_ms_block);
                        match tokio::time::timeout(
                            Duration::from_millis(hydration_timeout_ms),
                            crate::utils::rpc::RobustRpc::get_block_full_tolerant_with_hydration_pool_retry(
                                &hydration_pool_clone,
                                block_hash,
                                3,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(Some(block_full))) => {
                                FULL_BLOCK_HYDRATION_FAILURE_STREAK.store(0, Ordering::Relaxed);
                                Some(block_full)
                            }
                            Ok(Ok(None)) => None,
                            Ok(Err(err)) => {
                                let raw_err = err.to_string();
                                persist_unknown_opstack_decode(
                                    contracts_db_block.as_ref(),
                                    block_num,
                                    None,
                                    "block_full",
                                    &raw_err,
                                );
                                let err_msg = compact_error(&raw_err);
                                if looks_like_decode_incompatibility(&err_msg) {
                                    FULL_BLOCK_HYDRATION_ENABLED.store(false, Ordering::Relaxed);
                                    if retry_ms > 0 {
                                        FULL_BLOCK_HYDRATION_DISABLED_UNTIL_MS.store(
                                            now_ms().saturating_add(retry_ms),
                                            Ordering::Relaxed,
                                        );
                                    }
                                    warn_scan_throttled(format!(
                                        "[SCAN] Alloy BlockTransactions decode incompatibility at block #{} ({}). Entering tolerant hash/receipt mode; unparseable tx types will be skipped individually.",
                                        block_num,
                                        err_msg
                                    ));
                                } else if looks_like_provider_pressure(&err_msg) {
                                    is_rate_limited_error(&err_msg);
                                    let streak = FULL_BLOCK_HYDRATION_FAILURE_STREAK
                                        .fetch_add(1, Ordering::Relaxed)
                                        .saturating_add(1);
                                    warn_scan_throttled(format!(
                                        "[SCAN] Block #{} full hydration pressure failure (streak={} timeout={}ms): {}. Falling back to hash mode.",
                                        block_num,
                                        streak,
                                        hydration_timeout_ms,
                                        err_msg
                                    ));
                                } else {
                                    FULL_BLOCK_HYDRATION_FAILURE_STREAK.store(0, Ordering::Relaxed);
                                    warn_scan_throttled(format!(
                                        "[SCAN] Block #{} full hydration failed: {}. Falling back to hash mode.",
                                        block_num, err_msg
                                    ));
                                }
                                None
                            }
                            Err(_) => {
                                let streak = FULL_BLOCK_HYDRATION_FAILURE_STREAK
                                    .fetch_add(1, Ordering::Relaxed)
                                    .saturating_add(1);
                                warn_scan_throttled(format!(
                                    "[SCAN] Block #{} full hydration timed out after {}ms (streak={}). Falling back to hash mode.",
                                    block_num,
                                    hydration_timeout_ms,
                                    streak
                                ));
                                None
                            }
                        }
                    } else {
                        None
                    };

                    if let Some(block_full) = block_full {
                        let total_txs = block_full.transactions.len();
                        LAST_HYDRATED_BLOCK_TX_COUNT.store(total_txs as u32, Ordering::Relaxed);
                        let prioritization = PrioritizationConfig {
                            chain_id: chain_id_block,
                            high_value_tvl_threshold_wei: high_value_tvl_threshold_wei_block,
                        };
                        let mut stats = IngestStats::default();
                        let mut dust_hits = 0;
                        let mut high_value_probe_budget = HighValueProbeBudget::new(
                            load_high_value_probes_per_block(),
                            load_high_value_deployment_probes_per_block(),
                        );
                        let full_block_ingest_parallelism = load_full_block_ingest_parallelism();
                        let deferred_high_value_probe_budget_per_block =
                            load_full_block_deferred_high_value_probes_per_block();
                        let max_dust_candidates = load_dust_candidate_set_max_per_block();
                        let full_block_log_enrichment_enabled =
                            load_full_block_log_enrichment_enabled();
                        let mut queued_targets: HashSet<Address> = HashSet::new();
                        let mut dust_candidates: HashSet<Address> = HashSet::new();
                        let mut interesting_addrs: Vec<Address> = Vec::new();
                        let mut log_enrichment_hits = 0usize;

                        for tx in block_full.transactions.into_transactions() {
                            let to = tx.to();
                            let input = tx.input();

                            if to.is_none() {
                                stats.deploys = stats.deploys.saturating_add(1);
                                if prioritization.high_value_tvl_threshold_wei == U256::ZERO
                                    || high_value_probe_budget.reserve_deployment_probe()
                                {
                                    log_target_deployment(&provider_clone, &tx, &sender_clone).await;
                                }
                                continue;
                            }

                            let Some(to_addr) = to else {
                                continue;
                            };
                            if FastFilter::is_interesting(to, input) {
                                interesting_addrs.push(to_addr);
                            } else if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
                                bounded_insert_dust_candidate(
                                    &mut dust_candidates,
                                    to_addr,
                                    max_dust_candidates,
                                );
                            }
                        }

                        if full_block_log_enrichment_enabled
                            && !crate::utils::rpc::global_rpc_cooldown_active()
                        {
                            let enrichment_budget =
                                load_full_block_log_enrichment_max_addrs_per_block();
                            if enrichment_budget > 0 {
                                let enrichment_timeout_ms =
                                    load_full_block_log_enrichment_timeout_ms();
                                let enrichment_max_logs =
                                    load_full_block_log_enrichment_max_logs_per_block();
                                let enrichment_max_topics_per_log =
                                    load_full_block_log_enrichment_max_topics_per_log();
                                let logs_filter = alloy::rpc::types::Filter::new()
                                    .from_block(block_num)
                                    .to_block(block_num);
                                if let Ok(permit) = receipt_fallback_semaphore().acquire().await {
                                    let logs_lookup = tokio::time::timeout(
                                        Duration::from_millis(enrichment_timeout_ms),
                                        provider_clone.get_logs(&logs_filter),
                                    )
                                    .await;
                                    drop(permit);

                                    match logs_lookup {
                                        Ok(Ok(logs)) => {
                                            let mut enriched: HashSet<Address> = HashSet::new();

                                            for log in logs.into_iter().take(enrichment_max_logs) {
                                                let _ = crate::solver::watch_cache::ingest_amm_log(&log);
                                                if log_enrichment_hits >= enrichment_budget {
                                                    break;
                                                }
                                                push_log_enriched_candidate(
                                                    log.address(),
                                                    &mut enriched,
                                                    &mut interesting_addrs,
                                                    &mut log_enrichment_hits,
                                                );
                                                if log_enrichment_hits >= enrichment_budget {
                                                    break;
                                                }
                                                for topic in
                                                    log.topics().iter().skip(1).take(enrichment_max_topics_per_log)
                                                {
                                                    if let Some(addr) = topic_indexed_address(topic) {
                                                        push_log_enriched_candidate(
                                                            addr,
                                                            &mut enriched,
                                                            &mut interesting_addrs,
                                                            &mut log_enrichment_hits,
                                                        );
                                                        if log_enrichment_hits >= enrichment_budget {
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(Err(err)) => {
                                            let msg = compact_error(err);
                                            if is_rate_limited_error(&msg) {
                                                warn_scan_throttled(format!(
                                                    "[SCAN] Full-block log enrichment skipped at block #{} due to provider pressure: {}",
                                                    block_num, msg
                                                ));
                                            } else {
                                                tracing::debug!(
                                                    "[SCAN] Full-block log enrichment failed at block #{}: {}",
                                                    block_num,
                                                    msg
                                                );
                                            }
                                        }
                                        Err(_) => {
                                            warn_scan_throttled(format!(
                                                "[SCAN] Full-block log enrichment timed out at block #{} after {}ms.",
                                                block_num, enrichment_timeout_ms
                                            ));
                                        }
                                    }
                                }
                            }
                        }

                        let mut unique_interesting = Vec::new();
                        let mut seen_interesting = HashSet::new();
                        for addr in interesting_addrs {
                            if seen_interesting.insert(addr) {
                                unique_interesting.push(addr);
                            }
                        }

                        let high_value_gate_enabled =
                            prioritization.high_value_tvl_threshold_wei != U256::ZERO;
                        let mut high_value_matches = HashSet::new();
                        let mut deferred_high_value_candidates: Vec<Address> = Vec::new();
                        let mut in_flight = tokio::task::JoinSet::new();
                        let dispatch_probe = |address: Address,
                                              in_flight: &mut tokio::task::JoinSet<(Address, bool)>| {
                            let provider = Arc::clone(&provider_clone);
                            let chain_id = prioritization.chain_id;
                            let threshold = prioritization.high_value_tvl_threshold_wei;
                            in_flight.spawn(async move {
                                (
                                    address,
                                    contract_meets_high_value_tvl(
                                        &*provider,
                                        address,
                                        chain_id,
                                        threshold,
                                    )
                                    .await,
                                )
                            });
                        };

                        for address in unique_interesting.iter().copied() {
                            if !high_value_gate_enabled {
                                high_value_matches.insert(address);
                                continue;
                            }
                            if let Some(cached) = target_capital_estimate_eth_wei(address) {
                                if cached >= prioritization.high_value_tvl_threshold_wei {
                                    high_value_matches.insert(address);
                                }
                                continue;
                            }
                            deferred_high_value_candidates.push(address);
                        }

                        if high_value_gate_enabled {
                            if deferred_high_value_candidates.len()
                                > deferred_high_value_probe_budget_per_block
                            {
                                warn_scan_throttled(format!(
                                    "[SCAN] Full-block deferred high-value probe budget reached at block #{} (budget={} deferred_candidates={}).",
                                    block_num,
                                    deferred_high_value_probe_budget_per_block,
                                    deferred_high_value_candidates.len()
                                ));
                            }

                            for address in deferred_high_value_candidates
                                .into_iter()
                                .take(deferred_high_value_probe_budget_per_block)
                            {
                                if !high_value_probe_budget.reserve_target_probe(address) {
                                    continue;
                                }
                                while in_flight.len() >= full_block_ingest_parallelism {
                                    if let Some(Ok((addr, passed))) = in_flight.join_next().await {
                                        if passed {
                                            high_value_matches.insert(addr);
                                        }
                                    }
                                }
                                dispatch_probe(address, &mut in_flight);
                            }
                        }
                        while let Some(done) = in_flight.join_next().await {
                            if let Ok((addr, passed)) = done {
                                if passed {
                                    high_value_matches.insert(addr);
                                }
                            }
                        }

                        for address in unique_interesting {
                            if !high_value_matches.contains(&address) {
                                if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
                                    bounded_insert_dust_candidate(
                                        &mut dust_candidates,
                                        address,
                                        max_dust_candidates,
                                    );
                                }
                                continue;
                            }
                            if queued_targets.insert(address) {
                                let prio = if prioritization.high_value_tvl_threshold_wei == U256::ZERO {
                                    TargetPriority::Normal
                                } else {
                                    TargetPriority::Hot
                                };
                                let _accepted = sender_clone.enqueue(address, prio).await;
                                stats.matches = stats.matches.saturating_add(1);
                                enqueue_linked_contracts(
                                    &provider_clone,
                                    &sender_clone,
                                    address,
                                    prioritization,
                                    &mut queued_targets,
                                    &mut stats,
                                )
                                .await;
                            }
                        }

                        let capital_hits = enqueue_high_capital_dust_candidates(
                            &provider_clone,
                            &sender_clone,
                            prioritization,
                            contracts_db_block.as_ref(),
                            block_num,
                            &mut queued_targets,
                            &mut dust_candidates,
                        )
                        .await;

                        if dust_threshold_wei_block != U256::ZERO {
                            let max_dust_checks = load_dust_sweeper_max_per_block();
                            let mut candidates: Vec<Address> = dust_candidates.into_iter().collect();
                            candidates.truncate(max_dust_checks);
                            for candidate in candidates {
                                if queued_targets.contains(&candidate) {
                                    continue;
                                }
                                if contract_meets_dust_liquidity(
                                    &*provider_clone,
                                    candidate,
                                    dust_threshold_wei_block,
                                )
                                .await
                                    && queued_targets.insert(candidate)
                                {
                                    let _accepted =
                                        sender_clone.enqueue(candidate, TargetPriority::Dust).await;
                                    dust_hits += 1;
                                }
                            }
                        }

                        tracing::info!(
                            "[SCAN] Block #{}: {} txs | {} interesting | {} log-enriched | {} capital-profile | {} dust-liquidity | {} deploys",
                            block_num, total_txs, stats.matches, log_enrichment_hits, capital_hits, dust_hits, stats.deploys
                        );
                    } else {
                        let outcome = process_block_hash_mode(
                            &provider_clone,
                            &sender_clone,
                            block_num,
                            PrioritizationConfig {
                                chain_id: chain_id_block,
                                high_value_tvl_threshold_wei: high_value_tvl_threshold_wei_block,
                            },
                            dust_threshold_wei_block,
                            contracts_db_block.as_ref(),
                            Some(&hydration_pool_clone),
                        )
                        .await;
                        tracing::info!(
                            "[SCAN] Block #{} (hash mode): {} txs | {} interesting | {} capital-profile | {} dust-liquidity | {} deploys | {} receipt-fallback",
                            block_num,
                            outcome.total_txs,
                            outcome.interesting_hits,
                            outcome.capital_hits,
                            outcome.dust_hits,
                            outcome.deploys,
                            outcome.receipt_fallback_hits
                        );
                        if load_state_mining_enabled() {
                            let mut hash_mode_queued = HashSet::new();
                            run_state_mining_cycle(
                                &sender_clone,
                                &mut hash_mode_queued,
                                chain_id_block,
                                block_num,
                            ).await;
                        }
                    }
                    advance_last_good_head(&last_good_head_block, block_num);
                });
            }
        }
    }

    Ok(())
}

pub async fn start_backfill_worker(
    rpc_url: &str,
    target_sender: TargetQueueSender,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    contracts_db: Option<ContractsDb>,
) -> Result<()> {
    if !load_backfill_enabled() {
        tracing::info!("[BACKFILL] Disabled by BACKFILL_ENABLED.");
        return Ok(());
    }

    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
    let provider = Arc::new(provider);
    let high_value_tvl_threshold_wei = load_high_value_tvl_threshold();
    let chain_id_timeout_ms = load_chain_id_timeout_ms();
    let chain_id = match tokio::time::timeout(
        Duration::from_millis(chain_id_timeout_ms),
        provider.get_chain_id(),
    )
    .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(err)) => {
            return Err(anyhow::anyhow!(
                "[BACKFILL] Failed to fetch chain id: {}",
                compact_error(err)
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "[BACKFILL] Timed out fetching chain id after {}ms.",
                chain_id_timeout_ms
            ));
        }
    };
    let prioritization = PrioritizationConfig {
        chain_id,
        high_value_tvl_threshold_wei,
    };
    if high_value_tvl_threshold_wei != U256::ZERO {
        tracing::info!(
            "[BACKFILL] High-value TVL gate enabled for historical ingestion: threshold={} ETH-wei.",
            high_value_tvl_threshold_wei
        );
    } else {
        tracing::info!("[BACKFILL] High-value TVL gate disabled for historical ingestion.");
    }

    let start_offset = load_backfill_start_offset();
    let base_poll_ms = load_backfill_poll_ms();
    let mut poll_ms = base_poll_ms;
    let mut block_receipts_supported = true;
    let mut rate_limit_streak = 0u32;
    let mut last_backfill_error_log = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(30))
        .unwrap_or_else(std::time::Instant::now);
    let mut suppressed_backfill_errors: u64 = 0;
    let head_timeout_ms = load_head_fetch_timeout_ms();
    let latest = match tokio::time::timeout(
        Duration::from_millis(head_timeout_ms),
        provider.get_block_number(),
    )
    .await
    {
        Ok(Ok(head)) => head,
        Ok(Err(err)) => {
            return Err(anyhow::anyhow!(
                "[BACKFILL] Failed to fetch latest head: {}",
                compact_error(err)
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "[BACKFILL] Timed out fetching latest head after {}ms.",
                head_timeout_ms
            ));
        }
    };
    let mut cursor = latest.saturating_sub(start_offset);
    tracing::info!(
        "[BACKFILL] Started at block {} (latest={}, start_offset={}).",
        cursor,
        latest,
        start_offset
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("[BACKFILL] Shutdown signal received. Stopping backfill worker...");
                break;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_ms)) => {
                let mut queued_targets = HashSet::new();
                let mut sent = 0usize;
                let mut rate_limited_this_cycle = false;
                let block_receipts_timeout_ms = load_backfill_block_receipts_timeout_ms();
                let block_hash_timeout_ms = load_hash_mode_block_fetch_timeout_ms();
                let receipt_timeout_ms = load_hash_mode_receipt_fetch_timeout_ms();
                let mut log_backfill_error = |message: String| {
                    let now = std::time::Instant::now();
                    if now.duration_since(last_backfill_error_log) >= std::time::Duration::from_secs(10) {
                        if suppressed_backfill_errors > 0 {
                            tracing::warn!(
                                "{} ({} similar backfill warning(s) suppressed)",
                                message,
                                suppressed_backfill_errors
                            );
                            suppressed_backfill_errors = 0;
                        } else {
                            tracing::warn!("{}", message);
                        }
                        last_backfill_error_log = now;
                    } else {
                        suppressed_backfill_errors += 1;
                    }
                };

                if crate::utils::rpc::global_rpc_cooldown_active() {
                    log_backfill_error(
                        "[BACKFILL] Global RPC cooldown active; skipping cycle.".to_string(),
                    );
                    continue;
                }

                let mut receipts: Option<Vec<_>> = None;
                if block_receipts_supported {
                    match tokio::time::timeout(
                        Duration::from_millis(block_receipts_timeout_ms),
                        provider.get_block_receipts(cursor.into()),
                    )
                    .await
                    {
                        Err(_) => {
                            log_backfill_error(format!(
                                "[BACKFILL] Block receipts fetch timed out at {} after {}ms.",
                                cursor, block_receipts_timeout_ms
                            ));
                        }
                        Ok(Ok(Some(block_receipts))) => {
                            receipts = Some(block_receipts);
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(err)) => {
                            let raw_err = err.to_string();
                            let err_lc = raw_err.to_ascii_lowercase();
                            persist_unknown_opstack_decode(
                                contracts_db.as_ref(),
                                cursor,
                                None,
                                "block_receipts",
                                &raw_err,
                            );
                            if err_lc.contains("method not found")
                                || err_lc.contains("-32601")
                                || looks_like_decode_incompatibility(&err_lc)
                            {
                                block_receipts_supported = false;
                                tracing::warn!(
                                    "[BACKFILL] Provider does not support eth_getBlockReceipts; switching to hash+receipt mode."
                                );
                            } else {
                                let msg = compact_error(&raw_err);
                                if is_rate_limited_error(&msg) {
                                    rate_limited_this_cycle = true;
                                }
                                log_backfill_error(format!(
                                    "[BACKFILL] Block receipts fetch failed at {}: {}",
                                    cursor,
                                    msg
                                ));
                            }
                        }
                    }
                }

                if let Some(block_receipts) = receipts {
                    for receipt in block_receipts {
                        if let Some(to_addr) = receipt.to() {
                            if maybe_enqueue_backfill_target(
                                &provider,
                                &target_sender,
                                &mut queued_targets,
                                to_addr,
                                prioritization,
                            )
                            .await
                            {
                                sent += 1;
                            }
                        }
                        if let Some(deployed_addr) = receipt.contract_address() {
                            if maybe_enqueue_backfill_target(
                                &provider,
                                &target_sender,
                                &mut queued_targets,
                                deployed_addr,
                                prioritization,
                            )
                            .await
                            {
                                sent += 1;
                            }
                        }
                    }
                } else {
                    // Fallback path for providers that do not support block receipts.
                    match tokio::time::timeout(
                        Duration::from_millis(block_hash_timeout_ms),
                        provider.get_block_by_number(
                            cursor.into(),
                            alloy::rpc::types::BlockTransactionsKind::Hashes,
                        ),
                    )
                    .await
                    {
                        Err(_) => {
                            log_backfill_error(format!(
                                "[BACKFILL] Block hash fetch timed out at {} after {}ms.",
                                cursor, block_hash_timeout_ms
                            ));
                        }
                        Ok(Ok(Some(block_hashes))) => {
                            if let Some(tx_hashes) = block_hashes.transactions.as_hashes() {
                                for tx_hash in tx_hashes {
                                    let receipt_lookup = {
                                        let permit = match receipt_fallback_semaphore().acquire().await {
                                            Ok(permit) => permit,
                                            Err(_) => break,
                                        };
                                        let lookup = tokio::time::timeout(
                                            Duration::from_millis(receipt_timeout_ms),
                                            provider.get_transaction_receipt(*tx_hash),
                                        )
                                        .await;
                                        drop(permit);
                                        lookup
                                    };
                                    match receipt_lookup {
                                        Ok(Ok(Some(receipt))) => {
                                            if let Some(to_addr) = receipt.to() {
                                                if maybe_enqueue_backfill_target(
                                                    &provider,
                                                    &target_sender,
                                                    &mut queued_targets,
                                                    to_addr,
                                                    prioritization,
                                                )
                                                .await
                                                {
                                                    sent += 1;
                                                }
                                            }
                                            if let Some(deployed_addr) = receipt.contract_address()
                                            {
                                                if maybe_enqueue_backfill_target(
                                                    &provider,
                                                    &target_sender,
                                                    &mut queued_targets,
                                                    deployed_addr,
                                                    prioritization,
                                                )
                                                .await
                                                {
                                                    sent += 1;
                                                }
                                            }
                                        }
                                        Ok(Ok(None)) => {}
                                        Ok(Err(err)) => {
                                            let raw_err = err.to_string();
                                            persist_unknown_opstack_decode(
                                                contracts_db.as_ref(),
                                                cursor,
                                                Some(*tx_hash),
                                                "backfill_tx_receipt",
                                                &raw_err,
                                            );
                                            let msg = compact_error(&raw_err);
                                            if is_rate_limited_error(&msg) {
                                                rate_limited_this_cycle = true;
                                            }
                                            tracing::debug!(
                                                "[BACKFILL] tx receipt fetch failed at block {} hash {:?}: {}",
                                                cursor,
                                                tx_hash,
                                                msg
                                            );
                                        }
                                        Err(_) => {
                                            tracing::debug!(
                                                "[BACKFILL] tx receipt timed out at block {} hash {:?} after {}ms.",
                                                cursor,
                                                tx_hash,
                                                receipt_timeout_ms
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(err)) => {
                            let raw_err = err.to_string();
                            persist_unknown_opstack_decode(
                                contracts_db.as_ref(),
                                cursor,
                                None,
                                "backfill_block_hashes",
                                &raw_err,
                            );
                            let msg = compact_error(&raw_err);
                            if is_rate_limited_error(&msg) {
                                rate_limited_this_cycle = true;
                            }
                            log_backfill_error(format!(
                                "[BACKFILL] Block hash fetch failed at {}: {}",
                                cursor,
                                msg
                            ));
                        }
                    }
                }

                if rate_limited_this_cycle {
                    rate_limit_streak = rate_limit_streak.saturating_add(1);
                    let backoff_pow = rate_limit_streak.min(5);
                    poll_ms = (base_poll_ms.saturating_mul(1u64 << backoff_pow)).min(30_000);
                    if rate_limit_streak >= 6 {
                        log_backfill_error(
                            "[BACKFILL] Repeated rate limits; pausing backfill for 120s."
                                .to_string(),
                        );
                        tokio::time::sleep(Duration::from_secs(120)).await;
                        tracing::info!("[BACKFILL] Resumed after 120s hard pause.");
                        rate_limit_streak = 0;
                        poll_ms = base_poll_ms;
                    }
                    continue;
                } else {
                    rate_limit_streak = 0;
                    poll_ms = base_poll_ms;
                }

                if sent > 0 {
                    tracing::info!(
                        "[BACKFILL] block {} queued {} historical target(s).",
                        cursor, sent
                    );
                }

                if cursor == 0 {
                    let latest_head = match tokio::time::timeout(
                        Duration::from_millis(head_timeout_ms),
                        provider.get_block_number(),
                    )
                    .await
                    {
                        Ok(Ok(head)) => head,
                        Ok(Err(err)) => {
                            log_backfill_error(format!(
                                "[BACKFILL] Latest head refresh failed: {}",
                                compact_error(err)
                            ));
                            continue;
                        }
                        Err(_) => {
                            log_backfill_error(format!(
                                "[BACKFILL] Latest head refresh timed out after {}ms.",
                                head_timeout_ms
                            ));
                            continue;
                        }
                    };
                    cursor = latest_head;
                } else {
                    cursor = cursor.saturating_sub(1);
                }
            }
        }
    }

    Ok(())
}

async fn log_target_deployment<P, T>(
    provider: &P,
    tx: &alloy::rpc::types::Transaction,
    sender: &TargetQueueSender,
) where
    P: Provider<T>,
    T: alloy::transports::Transport + Clone,
{
    // Access transaction hash via public field
    // Access transaction hash via TxEnvelope
    let tx_hash = tx.inner.tx_hash();
    let receipt_timeout_ms = load_log_deploy_receipt_timeout_ms();
    if let Ok(Ok(Some(receipt))) = tokio::time::timeout(
        Duration::from_millis(receipt_timeout_ms),
        provider.get_transaction_receipt(*tx_hash),
    )
    .await
    {
        if let Some(deployed_addr) = receipt.contract_address {
            tracing::info!("[SCANNER] New deployment detected: {:?}", deployed_addr);
            let _accepted = sender.enqueue(deployed_addr, TargetPriority::Dust).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        adaptive_hydration_timeout_ms, balance_of_calldata, build_capital_profiler_tokens,
        classify_unknown_opstack_tx_type, default_dust_liquidity_threshold,
        has_structural_hubris_surface, high_value_cache, load_backfill_enabled,
        load_backfill_poll_ms, load_backfill_start_offset, load_dust_sweeper_max_per_block,
        load_hash_mode_block_budget_ms, load_high_value_unknown_admit_budget_per_min,
        load_high_value_unknown_admit_cooldown_ms, load_timeout_ms,
        load_ws_gap_replay_max_blocks_per_iteration, log_light_high_value_probes_per_min,
        log_light_max_addrs_per_min, looks_like_decode_incompatibility, meets_dust_liquidity,
        parse_bytes_hex, remember_structural_hubris, structural_hubris_cache, token_decimals,
        token_price_eth_wei, LAST_HYDRATED_BLOCK_TX_COUNT,
    };
    use alloy::primitives::{address, Address, Bytes, U256};
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_meets_dust_liquidity_threshold() {
        let threshold = default_dust_liquidity_threshold();
        let below = U256::from(30_000_000_000_000_000u128);
        let above = U256::from(50_000_000_000_000_000u128);
        assert!(!meets_dust_liquidity(below, threshold));
        assert!(meets_dust_liquidity(threshold, threshold));
        assert!(meets_dust_liquidity(above, threshold));
    }

    #[test]
    fn test_backfill_env_parsing_defaults_and_overrides() {
        let old_enabled = std::env::var("BACKFILL_ENABLED").ok();
        let old_offset = std::env::var("BACKFILL_START_OFFSET").ok();
        let old_poll = std::env::var("BACKFILL_POLL_MS").ok();

        std::env::remove_var("BACKFILL_ENABLED");
        std::env::remove_var("BACKFILL_START_OFFSET");
        std::env::remove_var("BACKFILL_POLL_MS");
        assert!(load_backfill_enabled());
        assert_eq!(load_backfill_start_offset(), 50_000);
        assert_eq!(load_backfill_poll_ms(), 150);

        std::env::set_var("BACKFILL_ENABLED", "false");
        std::env::set_var("BACKFILL_START_OFFSET", "123");
        std::env::set_var("BACKFILL_POLL_MS", "77");
        assert!(!load_backfill_enabled());
        assert_eq!(load_backfill_start_offset(), 123);
        assert_eq!(load_backfill_poll_ms(), 77);

        match old_enabled {
            Some(v) => std::env::set_var("BACKFILL_ENABLED", v),
            None => std::env::remove_var("BACKFILL_ENABLED"),
        }
        match old_offset {
            Some(v) => std::env::set_var("BACKFILL_START_OFFSET", v),
            None => std::env::remove_var("BACKFILL_START_OFFSET"),
        }
        match old_poll {
            Some(v) => std::env::set_var("BACKFILL_POLL_MS", v),
            None => std::env::remove_var("BACKFILL_POLL_MS"),
        }
    }

    #[test]
    fn test_adaptive_hydration_timeout_scales_with_tx_hint() {
        LAST_HYDRATED_BLOCK_TX_COUNT.store(80, Ordering::Relaxed);
        let base = 1_500;
        assert_eq!(adaptive_hydration_timeout_ms(base), 1_500);

        LAST_HYDRATED_BLOCK_TX_COUNT.store(210, Ordering::Relaxed);
        assert_eq!(adaptive_hydration_timeout_ms(base), 2_250);
    }

    #[test]
    fn test_structural_hubris_detects_partial_token_surface() {
        // Dispatcher contains transfer + approve but no full ERC20 selector surface.
        let bytecode = Bytes::from(vec![
            0x63, 0xa9, 0x05, 0x9c, 0xbb, // transfer(address,uint256)
            0x63, 0x09, 0x5e, 0xa7, 0xb3, // approve(address,uint256)
            0xf1, // CALL
            0x00,
        ]);
        assert!(has_structural_hubris_surface(&bytecode));
    }

    #[test]
    fn test_balance_of_calldata_uses_abi_address_layout() {
        let owner = Address::from([0x77; 20]);
        let calldata = balance_of_calldata(owner);
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata.as_ref()[0..4], &[0x70, 0xa0, 0x82, 0x31]);
        assert_eq!(&calldata.as_ref()[4..16], &[0u8; 12]);
        assert_eq!(&calldata.as_ref()[16..36], owner.as_slice());
    }

    #[test]
    fn test_structural_hubris_cache_does_not_pollute_high_value_tvl_cache() {
        let addr = Address::from([0x44; 20]);
        let now = 42_000u64;

        high_value_cache().clear();
        structural_hubris_cache().clear();

        remember_structural_hubris(addr, now);

        let polluted = high_value_cache().get(&addr).map(|entry| *entry.value());
        assert!(
            polluted.is_none(),
            "structural-hubris hints must not set high-value TVL decision cache"
        );
    }

    #[test]
    fn test_decode_incompatibility_matches_opstack_extended_types() {
        assert!(looks_like_decode_incompatibility(
            "error: unknown variant `0x7e`, expected one of ..."
        ));
        assert!(looks_like_decode_incompatibility(
            "error: unknown variant `0x7d`, expected one of ..."
        ));
        assert!(looks_like_decode_incompatibility(
            "did not match any variant of untagged enum BlockTransactions"
        ));
    }

    #[test]
    fn test_unknown_opstack_type_classifier_extracts_0x7d_and_0x7e() {
        let kind_7e =
            classify_unknown_opstack_tx_type("unknown variant `0x7e`, expected tagged tx");
        let kind_7d =
            classify_unknown_opstack_tx_type("unknown variant `0x7d`, expected tagged tx");
        assert_eq!(kind_7e.as_deref(), Some("unknown_tx_type_0x7e"));
        assert_eq!(kind_7d.as_deref(), Some("unknown_tx_type_0x7d"));
    }

    #[test]
    fn test_parse_bytes_hex_rejects_invalid_input() {
        assert!(parse_bytes_hex("0xzz").is_none());
        assert_eq!(parse_bytes_hex("0x").expect("empty bytes"), Bytes::new());
    }

    #[test]
    fn test_load_timeout_ms_clamps_values() {
        let key = "SCANNER_TEST_TIMEOUT_MS";
        let old = std::env::var(key).ok();

        std::env::set_var(key, "10");
        assert_eq!(load_timeout_ms(key, 500, 200, 5_000), 200);

        std::env::set_var(key, "99999");
        assert_eq!(load_timeout_ms(key, 500, 200, 5_000), 5_000);

        std::env::set_var(key, "750");
        assert_eq!(load_timeout_ms(key, 500, 200, 5_000), 750);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_ws_gap_replay_budget_env_clamps() {
        let key = "SCAN_WS_GAP_REPLAY_MAX_BLOCKS_PER_ITERATION";
        let old = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            load_ws_gap_replay_max_blocks_per_iteration(),
            super::DEFAULT_WS_GAP_REPLAY_MAX_BLOCKS_PER_ITERATION
        );
        std::env::set_var(key, "0");
        assert_eq!(load_ws_gap_replay_max_blocks_per_iteration(), 1);
        std::env::set_var(key, "999999");
        assert_eq!(load_ws_gap_replay_max_blocks_per_iteration(), 10_000);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_hash_mode_block_budget_env_clamps() {
        let key = "SCAN_HASH_MODE_BLOCK_BUDGET_MS";
        let old = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            load_hash_mode_block_budget_ms(),
            super::DEFAULT_HASH_MODE_BLOCK_BUDGET_MS
        );

        std::env::set_var(key, "10");
        assert_eq!(load_hash_mode_block_budget_ms(), 200);

        std::env::set_var(key, "999999");
        assert_eq!(load_hash_mode_block_budget_ms(), 30_000);

        std::env::set_var(key, "2500");
        assert_eq!(load_hash_mode_block_budget_ms(), 2_500);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_log_light_addr_budget_defaults_drop_under_high_value_gate() {
        let key = "SCAN_LOG_LIGHT_MAX_ADDRS_PER_MIN";
        let old = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            log_light_max_addrs_per_min(false),
            super::DEFAULT_LOG_LIGHT_MAX_ADDRS_PER_MIN
        );
        assert_eq!(
            log_light_max_addrs_per_min(true),
            super::DEFAULT_LOG_LIGHT_MAX_ADDRS_PER_MIN_TVL_GATED
        );

        std::env::set_var(key, "120");
        assert_eq!(log_light_max_addrs_per_min(true), 120);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_log_light_probe_budget_clamped_to_addr_budget() {
        let key = "SCAN_LOG_LIGHT_HIGH_VALUE_PROBES_PER_MIN";
        let old = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            log_light_high_value_probes_per_min(false, 75),
            75,
            "default probe budget must not exceed address budget"
        );
        assert_eq!(
            log_light_high_value_probes_per_min(true, 30),
            30,
            "high-value gated default probe budget must not exceed address budget"
        );

        std::env::set_var(key, "5000");
        assert_eq!(log_light_high_value_probes_per_min(true, 64), 64);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_token_decimals_handle_known_stables() {
        let chain = crate::config::chains::ChainConfig::mainnet();
        let overrides = HashMap::new();
        assert_eq!(token_decimals(chain.usdc, &chain, &overrides), 6);
        assert_eq!(
            token_decimals(
                address!("dAC17F958D2ee523a2206206994597C13D831ec7"),
                &chain,
                &overrides
            ),
            6
        );
        assert_eq!(
            token_decimals(
                address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
                &chain,
                &overrides
            ),
            18
        );
    }

    #[test]
    fn test_capital_profiler_tokens_filter_zero_weth() {
        let chain = crate::config::chains::ChainConfig {
            chain_id: 31337,
            name: "test".to_string(),
            weth: Address::ZERO,
            usdc: address!("1000000000000000000000000000000000000001"),
            stablecoins: vec![
                Address::ZERO,
                address!("1000000000000000000000000000000000000001"),
                address!("1000000000000000000000000000000000000002"),
                address!("1000000000000000000000000000000000000003"),
            ],
            known_tokens: Vec::new(),
            block_time_ms: 2_000,
            max_bundle_gas: 20_000_000,
        };
        let tokens = build_capital_profiler_tokens(&chain);
        assert!(!tokens.contains(&Address::ZERO));
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], chain.usdc);
    }

    #[test]
    fn test_token_price_uses_override_for_custom_priority_token() {
        let chain = crate::config::chains::ChainConfig::base();
        let custom = address!("1111111111111111111111111111111111111111");
        let mut prices = HashMap::new();
        prices.insert(custom, U256::from(2_000_000_000_000_000_000u128));

        let priced = token_price_eth_wei(custom, &chain, U256::from(1u64), &prices);
        assert_eq!(priced, Some(U256::from(2_000_000_000_000_000_000u128)));

        let unknown = Address::from([0x22; 20]);
        let unpriced = token_price_eth_wei(unknown, &chain, U256::from(1u64), &prices);
        assert!(unpriced.is_none());
    }

    #[test]
    fn test_fast_filter_preserves_known_hot_selectors() {
        let to = Some(Address::from([0x11; 20]));
        let mut input = vec![0u8; 4 + 32];
        input[0..4].copy_from_slice(&crate::utils::selectors::TRANSFER);
        let input = Bytes::from(input);
        assert!(super::FastFilter::is_interesting(to, &input));
    }

    #[test]
    fn test_dust_sweeper_max_per_block_env() {
        let key = "SCAN_DUST_SWEEPER_MAX_PER_BLOCK";
        let old = std::env::var(key).ok();

        std::env::remove_var(key);
        assert_eq!(
            load_dust_sweeper_max_per_block(),
            super::DEFAULT_DUST_SWEEPER_MAX_PER_BLOCK
        );

        std::env::set_var(key, "17");
        assert_eq!(load_dust_sweeper_max_per_block(), 17);

        std::env::set_var(key, "0");
        assert_eq!(
            load_dust_sweeper_max_per_block(),
            super::DEFAULT_DUST_SWEEPER_MAX_PER_BLOCK
        );

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_high_value_unknown_admit_env_parsing() {
        let budget_key = "SCAN_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN";
        let cooldown_key = "SCAN_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS";
        let old_budget = std::env::var(budget_key).ok();
        let old_cooldown = std::env::var(cooldown_key).ok();

        std::env::remove_var(budget_key);
        std::env::remove_var(cooldown_key);
        assert_eq!(
            load_high_value_unknown_admit_budget_per_min(),
            super::DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN
        );
        assert_eq!(
            load_high_value_unknown_admit_cooldown_ms(),
            super::DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS
        );

        std::env::set_var(budget_key, "7");
        std::env::set_var(cooldown_key, "45000");
        assert_eq!(load_high_value_unknown_admit_budget_per_min(), 7);
        assert_eq!(load_high_value_unknown_admit_cooldown_ms(), 45_000);

        std::env::set_var(budget_key, "0");
        std::env::set_var(cooldown_key, "200");
        assert_eq!(
            load_high_value_unknown_admit_budget_per_min(),
            super::DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN
        );
        assert_eq!(
            load_high_value_unknown_admit_cooldown_ms(),
            super::DEFAULT_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS
        );

        match old_budget {
            Some(v) => std::env::set_var(budget_key, v),
            None => std::env::remove_var(budget_key),
        }
        match old_cooldown {
            Some(v) => std::env::set_var(cooldown_key, v),
            None => std::env::remove_var(cooldown_key),
        }
    }

    #[test]
    fn test_normalize_scanner_now_ms_never_returns_zero() {
        super::LAST_SCANNER_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_scanner_now_ms(None), 1);
        assert!(super::normalize_scanner_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_scanner_now_ms_clamps_clock_regressions() {
        super::LAST_SCANNER_NOW_MS.store(2500, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_scanner_now_ms(Some(2200)), 2500);
        assert_eq!(super::normalize_scanner_now_ms(Some(2800)), 2800);
    }
}
