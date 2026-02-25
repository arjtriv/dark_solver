//! Dynamic Gas Optimality Solver
//!
//! Calculates the minimum tip needed to get a bundle included while
//! preserving at least 50% of expected profit. Uses `eth_feeHistory`
//! percentiles as a competitive baseline.

use alloy::primitives::keccak256;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use tokio::sync::RwLock;

/// Gas optimality solver that computes the minimum profitable tip.
///
/// # Strategy
/// ```text
/// tip = clamp(
///     lower = p25_priority_fee,                    // floor: must beat 25th percentile
///     value = (profit * MAX_TIP_FRACTION) / gas,   // target: fraction of profit per gas unit
///     upper = p75_priority_fee                     // ceiling: no need to overpay
/// )
/// ```
///
/// This ensures:
/// - We always bid above p25 (competitive inclusion)
/// - We never spend more than 50% of profit (profitability preservation)
/// - We don't bid above p75 (no overpayment vs. competitors)
#[derive(Debug, Clone)]
pub struct GasOptimalitySolver {
    pub base_fee: u128,
    /// Fee percentiles from `eth_feeHistory`: [p10, p25, p50, p75, p90]
    pub priority_fee_percentiles: Vec<u128>,
    /// Momentum/PID-style tip bump (wei/gas), inferred from recent fee-history trend.
    pub momentum_tip_bump_wei: u128,
    /// Best-effort head block number inferred from the `eth_feeHistory` response.
    pub head_block: Option<u64>,
}

/// Maximum fraction of profit to allocate to tips (75% = keep at least a quarter).
/// Maximum fraction of profit to allocate to tips.
/// Normal Mode: 75% (keep at least a quarter).
/// War Mode: 99% (win at all costs).
const MAX_TIP_FRACTION_NORMAL_NUM: u128 = 3;
const MAX_TIP_FRACTION_NORMAL_DEN: u128 = 4;
const MAX_TIP_FRACTION_WAR_NUM: u128 = 99;
const MAX_TIP_FRACTION_WAR_DEN: u128 = 100;

/// Default gas estimate if unknown (typical complex DeFi interaction).
pub const DEFAULT_GAS_ESTIMATE: u64 = 500_000;

const OPSTACK_GAS_PRICE_ORACLE_ADDR: &str = "0x420000000000000000000000000000000000000F";
const OPSTACK_L1_BASE_FEE_SELECTOR_SIG: &str = "l1BaseFee()";
const OPSTACK_OVERHEAD_SELECTOR_SIG: &str = "overhead()";
const OPSTACK_SCALAR_SELECTOR_SIG: &str = "scalar()";
const OPSTACK_DECIMALS_SELECTOR_SIG: &str = "decimals()";
const OPSTACK_L1_FEE_CALL_TIMEOUT_MS: u64 = 250;
const FEE_HISTORY_TIMEOUT_MS: u64 = 1_200;
const CONSERVATIVE_BASE_FEE_WEI: u128 = 30_000_000_000; // 30 gwei
const CONSERVATIVE_PRIORITY_FEE_PERCENTILES_WEI: [u128; 5] = [
    1_000_000_000,  // p10: 1 gwei
    2_000_000_000,  // p25: 2 gwei
    5_000_000_000,  // p50: 5 gwei
    10_000_000_000, // p75: 10 gwei
    20_000_000_000, // p90: 20 gwei
];

fn load_war_mode() -> bool {
    std::env::var("WAR_MODE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

const DEFAULT_GAS_MOMENTUM_ORACLE_ENABLED: bool = true;
const DEFAULT_GAS_MOMENTUM_KP_BPS: u128 = 500; // 0.05
const DEFAULT_GAS_MOMENTUM_KI_BPS: u128 = 150; // 0.015
const DEFAULT_GAS_MOMENTUM_KD_BPS: u128 = 300; // 0.03
const DEFAULT_ADAPTIVE_WINLOSS_ENABLED: bool = true;
const DEFAULT_ADAPTIVE_AGGRESSION_START_BPS: u64 = 10_000; // 1.00x (neutral baseline)
const DEFAULT_ADAPTIVE_AGGRESSION_MIN_BPS: u64 = 5_000; // 0.50x
const DEFAULT_ADAPTIVE_AGGRESSION_MAX_BPS: u64 = 30_000; // 3.00x
const ADAPTIVE_AGGRESSION_STEP_OUTBID_BPS: u64 = 1_000; // +0.10x
const ADAPTIVE_AGGRESSION_STEP_WON_BPS: u64 = 250; // -0.025x

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveBidFeedback {
    Outbid,
    Won,
}

fn load_adaptive_winloss_enabled() -> bool {
    std::env::var("GAS_ADAPTIVE_WINLOSS_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_ADAPTIVE_WINLOSS_ENABLED)
}

fn load_adaptive_scalar_start_bps() -> u64 {
    std::env::var("GAS_ADAPTIVE_AGGRESSION_START_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1_000, 100_000))
        .unwrap_or(DEFAULT_ADAPTIVE_AGGRESSION_START_BPS)
}

fn load_adaptive_scalar_min_bps() -> u64 {
    std::env::var("GAS_ADAPTIVE_AGGRESSION_MIN_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1_000, 100_000))
        .unwrap_or(DEFAULT_ADAPTIVE_AGGRESSION_MIN_BPS)
}

fn load_adaptive_scalar_max_bps() -> u64 {
    std::env::var("GAS_ADAPTIVE_AGGRESSION_MAX_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(1_000, 100_000))
        .unwrap_or(DEFAULT_ADAPTIVE_AGGRESSION_MAX_BPS)
}

fn adaptive_scalar_bounds() -> (u64, u64) {
    let mut min = load_adaptive_scalar_min_bps();
    let mut max = load_adaptive_scalar_max_bps();
    if min > max {
        std::mem::swap(&mut min, &mut max);
    }
    (min, max)
}

fn adaptive_scalar_state() -> &'static Mutex<u64> {
    static STATE: OnceLock<Mutex<u64>> = OnceLock::new();
    STATE.get_or_init(|| {
        let (min, max) = adaptive_scalar_bounds();
        let start = load_adaptive_scalar_start_bps().clamp(min, max);
        Mutex::new(start)
    })
}

fn adaptive_scalar_bps() -> u64 {
    if !load_adaptive_winloss_enabled() {
        return DEFAULT_ADAPTIVE_AGGRESSION_START_BPS;
    }
    let lock = adaptive_scalar_state().lock();
    match lock {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

fn scale_tip_by_bps(tip_wei: u128, scalar_bps: u64) -> u128 {
    tip_wei
        .saturating_mul(scalar_bps as u128)
        .saturating_div(10_000)
}

pub fn record_adaptive_feedback(feedback: AdaptiveBidFeedback) {
    if !load_adaptive_winloss_enabled() {
        return;
    }
    let (min_bps, max_bps) = adaptive_scalar_bounds();
    let lock = adaptive_scalar_state().lock();
    let mut scalar_bps = match lock {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let next = match feedback {
        AdaptiveBidFeedback::Outbid => {
            scalar_bps.saturating_add(ADAPTIVE_AGGRESSION_STEP_OUTBID_BPS)
        }
        AdaptiveBidFeedback::Won => scalar_bps.saturating_sub(ADAPTIVE_AGGRESSION_STEP_WON_BPS),
    };
    *scalar_bps = next.clamp(min_bps, max_bps);
}

pub fn is_opstack_chain(chain_id: u64) -> bool {
    matches!(chain_id, 10 | 8453)
}

fn load_gas_momentum_oracle_enabled() -> bool {
    std::env::var("GAS_MOMENTUM_ORACLE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_GAS_MOMENTUM_ORACLE_ENABLED)
}

fn load_gas_momentum_pid_gain_bps(key: &str, default_value: u128) -> u128 {
    std::env::var(key)
        .ok()
        .and_then(|raw| raw.trim().parse::<u128>().ok())
        .unwrap_or(default_value)
        .min(50_000)
}

fn parse_base_fee_series(result: &serde_json::Value) -> Vec<u128> {
    result["baseFeePerGas"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn compute_momentum_tip_bump_wei(result: &serde_json::Value) -> u128 {
    if !load_gas_momentum_oracle_enabled() {
        return 0;
    }

    let series = parse_base_fee_series(result);
    if series.len() < 3 {
        return 0;
    }

    let latest = *series.last().unwrap_or(&0);
    let prev = series
        .get(series.len().saturating_sub(2))
        .copied()
        .unwrap_or(0);
    let lookback = series.len().saturating_sub(1);
    let recent_count = lookback.min(3);
    if recent_count == 0 {
        return 0;
    }
    let recent_start = lookback.saturating_sub(recent_count);
    let recent_slice = &series[recent_start..lookback];
    let avg_recent = if recent_slice.is_empty() {
        0
    } else {
        recent_slice
            .iter()
            .copied()
            .sum::<u128>()
            .saturating_div(recent_slice.len() as u128)
    };

    let error = latest.saturating_sub(avg_recent);
    let derivative = latest.saturating_sub(prev);
    let mut integral = 0u128;
    for pair in series.windows(2).rev().take(4) {
        let next = pair[1];
        let prior = pair[0];
        integral = integral.saturating_add(next.saturating_sub(prior));
    }

    let kp = load_gas_momentum_pid_gain_bps("GAS_MOMENTUM_KP_BPS", DEFAULT_GAS_MOMENTUM_KP_BPS);
    let ki = load_gas_momentum_pid_gain_bps("GAS_MOMENTUM_KI_BPS", DEFAULT_GAS_MOMENTUM_KI_BPS);
    let kd = load_gas_momentum_pid_gain_bps("GAS_MOMENTUM_KD_BPS", DEFAULT_GAS_MOMENTUM_KD_BPS);

    error
        .saturating_mul(kp)
        .saturating_add(integral.saturating_mul(ki))
        .saturating_add(derivative.saturating_mul(kd))
        / 10_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpStackL1BaseFeeCacheEntry {
    chain_id: u64,
    block_number: u64,
    l1_base_fee_wei: u128,
}

/// Thread-safe, block-locked cache that ensures at most one poll per block height.
#[derive(Debug, Default)]
pub struct OpStackL1BaseFeeBlockCache {
    inner: RwLock<Option<OpStackL1BaseFeeCacheEntry>>,
}

impl OpStackL1BaseFeeBlockCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    pub async fn get_or_fetch<F, Fut>(
        &self,
        chain_id: u64,
        block_number: u64,
        fetch: F,
    ) -> Option<u128>
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = Option<u128>>,
    {
        {
            let guard = self.inner.read().await;
            if let Some(entry) = *guard {
                if entry.chain_id == chain_id && entry.block_number == block_number {
                    return Some(entry.l1_base_fee_wei);
                }
            }
        }

        let mut guard = self.inner.write().await;
        if let Some(entry) = *guard {
            if entry.chain_id == chain_id && entry.block_number == block_number {
                return Some(entry.l1_base_fee_wei);
            }
        }

        let fee = fetch(block_number).await?;
        *guard = Some(OpStackL1BaseFeeCacheEntry {
            chain_id,
            block_number,
            l1_base_fee_wei: fee,
        });
        Some(fee)
    }
}

static OPSTACK_L1_BASE_FEE_CACHE: OnceLock<OpStackL1BaseFeeBlockCache> = OnceLock::new();
static LAST_GOOD_GAS_SOLVER: OnceLock<Mutex<Option<GasOptimalitySolver>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpStackL1FeeParamsCacheEntry {
    chain_id: u64,
    block_number: u64,
    l1_base_fee_wei: u128,
    overhead: u128,
    scalar: u128,
    decimals: u32,
}

#[derive(Debug, Default)]
struct OpStackL1FeeParamsBlockCache {
    inner: RwLock<Option<OpStackL1FeeParamsCacheEntry>>,
}

impl OpStackL1FeeParamsBlockCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    async fn get_or_fetch<F, Fut>(
        &self,
        chain_id: u64,
        block_number: u64,
        fetch: F,
    ) -> Option<OpStackL1FeeParamsCacheEntry>
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = Option<OpStackL1FeeParamsCacheEntry>>,
    {
        {
            let guard = self.inner.read().await;
            if let Some(entry) = *guard {
                if entry.chain_id == chain_id && entry.block_number == block_number {
                    return Some(entry);
                }
            }
        }

        let mut guard = self.inner.write().await;
        if let Some(entry) = *guard {
            if entry.chain_id == chain_id && entry.block_number == block_number {
                return Some(entry);
            }
        }

        let entry = fetch(block_number).await?;
        *guard = Some(entry);
        Some(entry)
    }
}

static OPSTACK_L1_FEE_PARAMS_CACHE: OnceLock<OpStackL1FeeParamsBlockCache> = OnceLock::new();

fn selector_4(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash.0[0], hash.0[1], hash.0[2], hash.0[3]]
}

fn encode_selector_call(selector: [u8; 4]) -> String {
    // 4-byte selector only; no args.
    format!(
        "0x{:02x}{:02x}{:02x}{:02x}",
        selector[0], selector[1], selector[2], selector[3]
    )
}

fn parse_u128_from_32byte_hex_word(raw: &str) -> Option<u128> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let hex = hex.strip_prefix("0X").unwrap_or(hex);
    if hex.is_empty() {
        return None;
    }
    let significant = hex.trim_start_matches('0');
    if significant.len() > 64 {
        // Reject oversized words instead of silently truncating high bytes.
        return None;
    }
    let normalized = if significant.is_empty() {
        "0"
    } else {
        significant
    };

    // Left-pad to 32 bytes.
    let mut buf = [0u8; 32];
    let mut out_idx = 32usize;
    let mut i = normalized.len();
    while i > 0 && out_idx > 0 {
        let start = i.saturating_sub(2);
        let byte_str = &normalized[start..i];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        out_idx = out_idx.saturating_sub(1);
        buf[out_idx] = byte;
        i = start;
    }

    // Take low 16 bytes -> u128
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&buf[16..32]);
    Some(u128::from_be_bytes(tail))
}

pub fn estimate_l1_data_fee_wei_from_len(tx_data_len: usize, l1_gas_price_wei: u128) -> u128 {
    (tx_data_len as u128).saturating_mul(l1_gas_price_wei)
}

fn encode_block_tag_hex(block_number: u64) -> String {
    format!("0x{block_number:x}")
}

fn timeout_http_client(timeout_ms: u64) -> reqwest::Client {
    match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            eprintln!(
                "[EXEC] Warning: failed to construct gas-solver timeout HTTP client: {err}. Falling back to default client."
            );
            reqwest::Client::new()
        }
    }
}

async fn fetch_opstack_oracle_u128_at_block(
    rpc_url: &str,
    block_number: u64,
    selector_sig: &str,
) -> Option<u128> {
    let client = timeout_http_client(OPSTACK_L1_FEE_CALL_TIMEOUT_MS);
    let data = encode_selector_call(selector_4(selector_sig));
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": OPSTACK_GAS_PRICE_ORACLE_ADDR,
                "data": data,
            },
            encode_block_tag_hex(block_number)
        ]
    });

    let resp = tokio::time::timeout(
        std::time::Duration::from_millis(OPSTACK_L1_FEE_CALL_TIMEOUT_MS),
        client.post(rpc_url).json(&payload).send(),
    )
    .await
    .ok()?
    .ok()?;
    let body = tokio::time::timeout(
        std::time::Duration::from_millis(OPSTACK_L1_FEE_CALL_TIMEOUT_MS),
        resp.json::<serde_json::Value>(),
    )
    .await
    .ok()?
    .ok()?;
    if body.get("error").is_some() {
        return None;
    }
    let result = body.get("result")?.as_str()?;
    parse_u128_from_32byte_hex_word(result)
}

async fn fetch_opstack_l1_base_fee_wei_at_block(rpc_url: &str, block_number: u64) -> Option<u128> {
    // Minimal `eth_call` against the OP-stack GasPriceOracle predeploy at a fixed block.
    fetch_opstack_oracle_u128_at_block(rpc_url, block_number, OPSTACK_L1_BASE_FEE_SELECTOR_SIG)
        .await
}

async fn fetch_opstack_l1_base_fee_wei_latest(rpc_url: &str) -> Option<u128> {
    // Latest block tag version (legacy behavior).
    let client = timeout_http_client(OPSTACK_L1_FEE_CALL_TIMEOUT_MS);
    let data = encode_selector_call(selector_4(OPSTACK_L1_BASE_FEE_SELECTOR_SIG));
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {
                "to": OPSTACK_GAS_PRICE_ORACLE_ADDR,
                "data": data,
            },
            "latest"
        ]
    });

    let resp = tokio::time::timeout(
        std::time::Duration::from_millis(OPSTACK_L1_FEE_CALL_TIMEOUT_MS),
        client.post(rpc_url).json(&payload).send(),
    )
    .await
    .ok()?
    .ok()?;
    let body = tokio::time::timeout(
        std::time::Duration::from_millis(OPSTACK_L1_FEE_CALL_TIMEOUT_MS),
        resp.json::<serde_json::Value>(),
    )
    .await
    .ok()?
    .ok()?;
    if body.get("error").is_some() {
        return None;
    }
    let result = body.get("result")?.as_str()?;
    parse_u128_from_32byte_hex_word(result)
}

/// Estimate the OP-stack L1 data fee (wei) using the on-chain oracle's current `l1BaseFee()`.
///
/// Current implementation uses a linear approximation:
/// `l1_data_fee_wei = tx_data_len * l1BaseFee_wei`.
///
/// Fail-open: returns `None` on RPC error/timeout.
pub async fn estimate_opstack_l1_data_fee_wei(rpc_url: &str, tx_data_len: usize) -> Option<u128> {
    let l1_base_fee_wei = fetch_opstack_l1_base_fee_wei_latest(rpc_url).await?;
    Some(estimate_l1_data_fee_wei_from_len(
        tx_data_len,
        l1_base_fee_wei,
    ))
}

/// Estimate the OP-stack L1 data fee (wei) with a block-locked global cache.
pub async fn estimate_opstack_l1_data_fee_wei_cached(
    rpc_url: &str,
    chain_id: u64,
    block_number: u64,
    tx_data_len: usize,
) -> Option<u128> {
    let cache = OPSTACK_L1_BASE_FEE_CACHE.get_or_init(OpStackL1BaseFeeBlockCache::new);
    let l1_base_fee_wei = cache
        .get_or_fetch(chain_id, block_number, |block| async move {
            fetch_opstack_l1_base_fee_wei_at_block(rpc_url, block).await
        })
        .await?;
    Some(estimate_l1_data_fee_wei_from_len(
        tx_data_len,
        l1_base_fee_wei,
    ))
}

pub fn opstack_l1_calldata_gas(data: &[u8]) -> u128 {
    let mut zeros = 0u128;
    let mut nonzeros = 0u128;
    for &b in data {
        if b == 0 {
            zeros = zeros.saturating_add(1);
        } else {
            nonzeros = nonzeros.saturating_add(1);
        }
    }
    zeros
        .saturating_mul(4)
        .saturating_add(nonzeros.saturating_mul(16))
}

pub fn opstack_l1_calldata_gas_chunks<'a, I>(chunks: I) -> (u128, usize)
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut gas = 0u128;
    let mut total_len = 0usize;
    for chunk in chunks {
        total_len = total_len.saturating_add(chunk.len());
        gas = gas.saturating_add(opstack_l1_calldata_gas(chunk));
    }
    (gas, total_len)
}

pub fn opstack_l1_fee_wei_from_calldata_gas(
    calldata_gas: u128,
    l1_base_fee_wei: u128,
    overhead: u128,
    scalar: u128,
    decimals: u32,
) -> u128 {
    let l1_gas_used = calldata_gas.saturating_add(overhead);
    let denom = 10u128.pow(decimals.min(18));
    if denom == 0 {
        return 0;
    }
    l1_gas_used
        .saturating_mul(l1_base_fee_wei)
        .saturating_mul(scalar)
        / denom
}

pub fn opstack_l1_fee_wei_from_calldata(
    data: &[u8],
    l1_base_fee_wei: u128,
    overhead: u128,
    scalar: u128,
    decimals: u32,
) -> u128 {
    // OP-stack (Bedrock-style) fee model:
    // l1_fee = (l1_gas_used + overhead) * l1BaseFee * scalar / 10^decimals
    //
    // "Exact" here means: we use the oracle-provided overhead/scalar/decimals and compute the
    // calldata gas from byte-level zero/nonzero costs (4/16).
    opstack_l1_fee_wei_from_calldata_gas(
        opstack_l1_calldata_gas(data),
        l1_base_fee_wei,
        overhead,
        scalar,
        decimals,
    )
}

async fn opstack_l1_fee_params_entry_cached(
    rpc_url: &str,
    chain_id: u64,
    block_number: u64,
) -> Option<OpStackL1FeeParamsCacheEntry> {
    let cache = OPSTACK_L1_FEE_PARAMS_CACHE.get_or_init(OpStackL1FeeParamsBlockCache::new);
    cache
        .get_or_fetch(chain_id, block_number, |block| async move {
            let l1_base_fee_wei = fetch_opstack_oracle_u128_at_block(
                rpc_url,
                block,
                OPSTACK_L1_BASE_FEE_SELECTOR_SIG,
            )
            .await?;
            let overhead =
                fetch_opstack_oracle_u128_at_block(rpc_url, block, OPSTACK_OVERHEAD_SELECTOR_SIG)
                    .await?;
            let scalar =
                fetch_opstack_oracle_u128_at_block(rpc_url, block, OPSTACK_SCALAR_SELECTOR_SIG)
                    .await?;
            let decimals_u128 =
                fetch_opstack_oracle_u128_at_block(rpc_url, block, OPSTACK_DECIMALS_SELECTOR_SIG)
                    .await?;
            let decimals: u32 = u32::try_from(decimals_u128).ok().filter(|v| *v <= 18)?;
            Some(OpStackL1FeeParamsCacheEntry {
                chain_id,
                block_number: block,
                l1_base_fee_wei,
                overhead,
                scalar,
                decimals,
            })
        })
        .await
}

pub async fn estimate_opstack_l1_fee_wei_exact_cached(
    rpc_url: &str,
    chain_id: u64,
    block_number: u64,
    calldata: &[u8],
) -> Option<u128> {
    let entry = opstack_l1_fee_params_entry_cached(rpc_url, chain_id, block_number).await?;

    Some(opstack_l1_fee_wei_from_calldata(
        calldata,
        entry.l1_base_fee_wei,
        entry.overhead,
        entry.scalar,
        entry.decimals,
    ))
}

pub async fn estimate_opstack_l1_fee_wei_exact_cached_from_gas(
    rpc_url: &str,
    chain_id: u64,
    block_number: u64,
    calldata_gas: u128,
) -> Option<u128> {
    let entry = opstack_l1_fee_params_entry_cached(rpc_url, chain_id, block_number).await?;
    Some(opstack_l1_fee_wei_from_calldata_gas(
        calldata_gas,
        entry.l1_base_fee_wei,
        entry.overhead,
        entry.scalar,
        entry.decimals,
    ))
}

impl GasOptimalitySolver {
    fn tip_budget_per_gas(&self, expected_profit_wei: u128, gas_used: u64) -> Option<u128> {
        if expected_profit_wei == 0 || gas_used == 0 {
            return None;
        }

        // Cost of base fee alone
        let base_cost = self.base_fee.saturating_mul(gas_used as u128);
        if base_cost >= expected_profit_wei {
            return None; // Can't even cover base fee
        }

        let remaining_profit = expected_profit_wei - base_cost;

        // Maximum tip we'd pay:
        // War Mode: 99% of remaining profit.
        // Normal Mode: 75% of remaining profit.
        let (num, den) = if load_war_mode() {
            (MAX_TIP_FRACTION_WAR_NUM, MAX_TIP_FRACTION_WAR_DEN)
        } else {
            (MAX_TIP_FRACTION_NORMAL_NUM, MAX_TIP_FRACTION_NORMAL_DEN)
        };

        let max_tip_total = remaining_profit.saturating_mul(num) / den;

        Some(max_tip_total / (gas_used as u128))
    }

    /// Create a solver with known fee data.
    pub fn new(base_fee: u128, percentiles: Vec<u128>) -> Self {
        Self {
            base_fee,
            priority_fee_percentiles: percentiles,
            momentum_tip_bump_wei: 0,
            head_block: None,
        }
    }

    /// Calculate the optimal priority fee per gas unit.
    ///
    /// Returns 0 if profit is zero or negative after base fee costs.
    pub fn optimal_tip(&self, expected_profit_wei: u128, gas_used: u64) -> u128 {
        let Some(max_tip_per_gas) = self.tip_budget_per_gas(expected_profit_wei, gas_used) else {
            return 0;
        };

        // Percentile floors/ceilings
        let p25 = self.percentile(25).unwrap_or(0);
        let p75 = self.percentile(75).unwrap_or(u128::MAX);

        // Clamp: max(p25, min(max_tip_per_gas, p75))
        let mut tip = max_tip_per_gas.min(p75).max(p25);
        if self.momentum_tip_bump_wei > 0 {
            let p90 = self.percentile(90).unwrap_or(u128::MAX);
            tip = tip
                .saturating_add(self.momentum_tip_bump_wei)
                .min(p90)
                .min(max_tip_per_gas);
        }

        // Final safety check: total gas cost must not exceed profit
        let total_gas_cost = (self.base_fee + tip).saturating_mul(gas_used as u128);
        if total_gas_cost >= expected_profit_wei {
            // Fall back to minimal viable tip
            return p25.min(max_tip_per_gas);
        }

        tip
    }

    /// Contested auto-scaling: if a competitor hint is present, try `p75 + 1 wei` *only* when
    /// it still respects the tip budget and remains profitable.
    pub fn optimal_tip_auto_scaled(
        &self,
        expected_profit_wei: u128,
        gas_used: u64,
        contested: bool,
    ) -> u128 {
        let base_tip = self.optimal_tip(expected_profit_wei, gas_used);
        let Some(max_tip_per_gas) = self.tip_budget_per_gas(expected_profit_wei, gas_used) else {
            return base_tip;
        };
        let mut tip = base_tip;

        if contested {
            let p75 = self.percentile(75).unwrap_or(u128::MAX);
            let p75_plus_one = p75.saturating_add(1);
            if p75_plus_one > tip && p75_plus_one <= max_tip_per_gas {
                let total_gas_cost =
                    (self.base_fee.saturating_add(p75_plus_one)).saturating_mul(gas_used as u128);
                if total_gas_cost < expected_profit_wei {
                    tip = p75_plus_one;
                }
            }
        }

        let p25 = self.percentile(25).unwrap_or(0);
        let p90 = self.percentile(90).unwrap_or(u128::MAX);
        let adaptive_tip = scale_tip_by_bps(tip, adaptive_scalar_bps())
            .max(p25)
            .min(max_tip_per_gas)
            .min(p90);
        let total_gas_cost =
            (self.base_fee.saturating_add(adaptive_tip)).saturating_mul(gas_used as u128);
        if total_gas_cost >= expected_profit_wei {
            return tip;
        }
        adaptive_tip
    }

    /// Compute `max_fee_per_gas` (EIP-1559).
    pub fn max_fee_per_gas(&self, tip: u128) -> u128 {
        // 2x base_fee headroom for base fee volatility + tip
        self.base_fee.saturating_mul(2).saturating_add(tip)
    }

    /// Get a specific percentile from the stored data.
    /// Percentiles stored as [p10, p25, p50, p75, p90].
    fn percentile(&self, pct: u8) -> Option<u128> {
        let idx = match pct {
            10 => 0,
            25 => 1,
            50 => 2,
            75 => 3,
            90 => 4,
            _ => return None,
        };
        self.priority_fee_percentiles.get(idx).copied()
    }

    /// Construct from live provider using `eth_feeHistory`.
    ///
    /// Fetches the last 10 blocks' priority fee percentiles.
    /// Falls back to last-known-good data (or conservative defaults) on RPC failure.
    pub async fn from_provider_url(rpc_url: &str) -> Self {
        // Build a minimal JSON-RPC request for eth_feeHistory
        let client = timeout_http_client(FEE_HISTORY_TIMEOUT_MS);
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_feeHistory",
            "params": ["0xa", "latest", [10, 25, 50, 75, 90]]
        });

        let send = tokio::time::timeout(
            std::time::Duration::from_millis(FEE_HISTORY_TIMEOUT_MS),
            client.post(rpc_url).json(&payload).send(),
        )
        .await;
        let Ok(Ok(resp)) = send else {
            return Self::last_known_or_conservative_fallback();
        };

        let body = tokio::time::timeout(
            std::time::Duration::from_millis(FEE_HISTORY_TIMEOUT_MS),
            resp.json::<serde_json::Value>(),
        )
        .await;
        let Ok(Ok(body)) = body else {
            return Self::last_known_or_conservative_fallback();
        };
        if body.get("error").is_some() {
            return Self::last_known_or_conservative_fallback();
        }

        let Some(parsed) = Self::parse_fee_history(&body) else {
            return Self::last_known_or_conservative_fallback();
        };
        if let Ok(mut slot) = LAST_GOOD_GAS_SOLVER.get_or_init(|| Mutex::new(None)).lock() {
            *slot = Some(parsed.clone());
        }
        parsed
    }

    /// Parse `eth_feeHistory` response into base_fee + percentile averages.
    fn parse_fee_history(body: &serde_json::Value) -> Option<Self> {
        let result = body.get("result")?;

        let oldest_block = result
            .get("oldestBlock")?
            .as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        let reward_len = result
            .get("reward")?
            .as_array()
            .map(|arr| arr.len() as u64)?;
        let head_block = oldest_block.and_then(|oldest| {
            reward_len
                .checked_sub(1)
                .map(|offset| oldest.saturating_add(offset))
        });

        // baseFeePerGas is an array of hex strings.
        let base_fee = result
            .get("baseFeePerGas")?
            .as_array()
            .and_then(|arr| arr.last())
            .and_then(|v| v.as_str())
            .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())?;

        // reward is an array of arrays of hex strings (per block, per percentile).
        let reward_arrays = result.get("reward")?.as_array()?;

        let mut avg_percentiles = vec![0u128; 5];
        let mut count = 0u128;

        for block_rewards in reward_arrays {
            let rewards = block_rewards.as_array()?;
            if rewards.len() < 5 {
                return None;
            }
            for (i, reward) in rewards.iter().enumerate().take(5) {
                let val = reward
                    .as_str()
                    .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())?;
                avg_percentiles[i] = avg_percentiles[i].saturating_add(val);
            }
            count += 1;
        }

        if count == 0 {
            return None;
        }
        for p in avg_percentiles.iter_mut() {
            *p /= count;
        }

        Some(Self {
            base_fee,
            priority_fee_percentiles: avg_percentiles,
            momentum_tip_bump_wei: compute_momentum_tip_bump_wei(result),
            head_block,
        })
    }

    fn last_known_or_conservative_fallback() -> Self {
        if let Ok(slot) = LAST_GOOD_GAS_SOLVER.get_or_init(|| Mutex::new(None)).lock() {
            if let Some(last_good) = slot.clone() {
                return last_good;
            }
        }
        Self::conservative_fallback()
    }

    /// Conservative defaults when RPC is unavailable and no cached fee history exists.
    fn conservative_fallback() -> Self {
        Self {
            base_fee: CONSERVATIVE_BASE_FEE_WEI,
            priority_fee_percentiles: CONSERVATIVE_PRIORITY_FEE_PERCENTILES_WEI.to_vec(),
            momentum_tip_bump_wei: 0,
            head_block: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_solver() -> GasOptimalitySolver {
        GasOptimalitySolver::new(
            1_000_000_000, // 1 gwei base fee
            vec![
                100_000_000,   // p10: 0.1 gwei
                200_000_000,   // p25: 0.2 gwei
                500_000_000,   // p50: 0.5 gwei
                1_000_000_000, // p75: 1 gwei
                2_000_000_000, // p90: 2 gwei
            ],
        )
    }

    #[test]
    fn test_zero_profit_returns_zero_tip() {
        let solver = test_solver();
        assert_eq!(solver.optimal_tip(0, 500_000), 0);
    }

    #[test]
    fn test_opstack_l1_calldata_gas_counts_zero_and_nonzero_bytes() {
        // 2 zero bytes (4 each) + 3 nonzero bytes (16 each) = 8 + 48 = 56
        let data = [0u8, 7u8, 0u8, 1u8, 2u8];
        assert_eq!(opstack_l1_calldata_gas(&data), 56);
    }

    #[test]
    fn test_opstack_l1_fee_wei_from_calldata_applies_overhead_scalar_and_decimals() {
        // data_gas = 16 (one nonzero)
        // l1_gas_used = 16 + overhead(84) = 100
        // fee = 100 * base(2) * scalar(1_000_000) / 10^6 = 200
        let data = [1u8];
        let fee = opstack_l1_fee_wei_from_calldata(&data, 2, 84, 1_000_000, 6);
        assert_eq!(fee, 200);
    }

    #[test]
    fn test_zero_gas_returns_zero_tip() {
        let solver = test_solver();
        assert_eq!(solver.optimal_tip(1_000_000_000_000_000_000, 0), 0);
    }

    #[test]
    fn test_tip_never_exceeds_half_profit() {
        let solver = test_solver();
        let profit = 1_000_000_000_000_000_000u128; // 1 ETH
        let gas = 500_000u64;

        let tip = solver.optimal_tip(profit, gas);
        let total_gas_cost = (solver.base_fee + tip) * gas as u128;

        // Total gas cost must be < 50% of profit (after base fee)
        assert!(
            total_gas_cost < profit,
            "total_gas_cost {} >= profit {}",
            total_gas_cost,
            profit
        );
    }

    #[test]
    fn test_tip_at_least_p25_when_profitable() {
        let solver = test_solver();
        let profit = 10_000_000_000_000_000_000u128; // 10 ETH (very profitable)
        let gas = 200_000u64;

        let tip = solver.optimal_tip(profit, gas);
        let p25 = 200_000_000u128; // 0.2 gwei

        assert!(tip >= p25, "tip {} < p25 {}", tip, p25);
    }

    #[test]
    fn test_unprofitable_after_base_fee_returns_zero() {
        let solver = test_solver();
        // Profit: 0.0001 ETH, Base fee cost for 500k gas: 0.5 ETH
        let profit = 100_000_000_000_000u128; // 0.0001 ETH
        let gas = 500_000u64;

        let tip = solver.optimal_tip(profit, gas);
        assert_eq!(tip, 0, "Should be 0 when base fee exceeds profit");
    }

    #[test]
    fn test_max_fee_per_gas() {
        let solver = test_solver();
        let tip = 500_000_000u128; // 0.5 gwei
        let max_fee = solver.max_fee_per_gas(tip);
        // 2 * base_fee + tip = 2 * 1 gwei + 0.5 gwei = 2.5 gwei
        assert_eq!(max_fee, 2_500_000_000);
    }

    #[test]
    fn test_contested_auto_scale_to_p75_plus_one_when_budget_allows() {
        let solver = test_solver();
        let profit = 10_000_000_000_000_000_000u128; // 10 ETH
        let gas = 200_000u64;

        let base_tip = solver.optimal_tip(profit, gas);
        let scaled = solver.optimal_tip_auto_scaled(profit, gas, true);
        let p75_plus_one = 1_000_000_000u128 + 1;

        assert!(
            base_tip <= 1_000_000_000u128,
            "base_tip should be capped at p75"
        );
        assert_eq!(scaled, p75_plus_one);
    }

    #[test]
    fn test_contested_auto_scale_skips_when_budget_too_small() {
        let solver = test_solver();
        // Very low profit: budget per gas will be < p75+1.
        let profit = 1_000_000_000_000_000u128; // 0.001 ETH
        let gas = 500_000u64;

        let base_tip = solver.optimal_tip(profit, gas);
        let scaled = solver.optimal_tip_auto_scaled(profit, gas, true);
        assert_eq!(scaled, base_tip);
    }

    #[test]
    fn test_parse_u128_from_32byte_hex_word_reads_low_128_bits() {
        // 0x...01 in the lowest byte.
        let raw = "0x0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(parse_u128_from_32byte_hex_word(raw), Some(1u128));

        // High bits set should be ignored when converting to u128.
        let raw_high = "0x0100000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(parse_u128_from_32byte_hex_word(raw_high), Some(0u128));
    }

    #[test]
    fn test_parse_u128_from_32byte_hex_word_rejects_oversized_significant_word() {
        // 65 significant nybbles (>32 bytes) should fail closed.
        let raw = "0x10000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(parse_u128_from_32byte_hex_word(raw), None);
    }

    #[test]
    fn test_estimate_l1_data_fee_linear() {
        assert_eq!(estimate_l1_data_fee_wei_from_len(0, 123), 0);
        assert_eq!(estimate_l1_data_fee_wei_from_len(10, 2), 20);
    }

    #[test]
    fn test_is_opstack_chain() {
        assert!(is_opstack_chain(10));
        assert!(is_opstack_chain(8453));
        assert!(!is_opstack_chain(1));
    }

    #[test]
    fn test_parse_fee_history_falls_back_on_jsonrpc_error_shape() {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32000, "message": "upstream failed" }
        });

        let parsed = GasOptimalitySolver::parse_fee_history(&body);
        assert!(parsed.is_none());
    }

    #[test]
    fn test_parse_fee_history_computes_positive_momentum_on_rising_base_fee() {
        std::env::set_var("GAS_MOMENTUM_ORACLE_ENABLED", "1");
        std::env::set_var("GAS_MOMENTUM_KP_BPS", "1000");
        std::env::set_var("GAS_MOMENTUM_KI_BPS", "300");
        std::env::set_var("GAS_MOMENTUM_KD_BPS", "700");

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "oldestBlock": "0x10",
                "baseFeePerGas": [
                    "0x3b9aca00", // 1.0 gwei
                    "0x4a817c80", // 1.25 gwei
                    "0x59682f00", // 1.5 gwei
                    "0x77359400"  // 2.0 gwei
                ],
                "reward": [
                    ["0x5f5e100","0xbebc200","0x17d78400","0x1dcd6500","0x2625a000"],
                    ["0x5f5e100","0xbebc200","0x17d78400","0x1dcd6500","0x2625a000"],
                    ["0x5f5e100","0xbebc200","0x17d78400","0x1dcd6500","0x2625a000"]
                ]
            }
        });

        let parsed = GasOptimalitySolver::parse_fee_history(&body).expect("valid fee history");
        assert!(parsed.momentum_tip_bump_wei > 0);
    }
}
