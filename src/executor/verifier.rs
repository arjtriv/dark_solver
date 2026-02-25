use crate::executor::multi_block::{advance_block_env, block_time_for_chain, MultiBlockExecutor};
use crate::fork_db::ForkDB;
use crate::solver::objectives::ExploitParams;
use alloy::primitives::Address;
use alloy::providers::Provider;
use anyhow::anyhow;
use revm::db::CacheDB;
use revm::primitives::{
    keccak256, AccountInfo, Address as RAddress, ExecutionResult, TransactTo, U256 as RU256,
};
use revm::{Database, DatabaseRef, Evm};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

fn u256_word_to_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 {
        return None;
    }
    if word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&word[24..32]);
    Some(u64::from_be_bytes(tail) as usize)
}

fn decode_revert_reason(output: &[u8]) -> Option<String> {
    if output.len() < 4 {
        return None;
    }
    // Error(string)
    if output[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let args = &output[4..];
        if args.len() < 64 {
            return None;
        }
        let offset = u256_word_to_usize(&args[0..32])?;
        if offset.saturating_add(32) > args.len() {
            return None;
        }
        let len = u256_word_to_usize(&args[offset..offset.saturating_add(32)])?;
        let start = offset.saturating_add(32);
        if start.saturating_add(len) > args.len() {
            return None;
        }
        let raw = &args[start..start.saturating_add(len)];
        return std::str::from_utf8(raw).ok().map(|s| s.to_string());
    }
    // Panic(uint256)
    if output[0..4] == [0x4e, 0x48, 0x7b, 0x71] {
        if output.len() < 4 + 32 {
            return None;
        }
        let code = u256_word_to_usize(&output[4..36]);
        return Some(match code {
            Some(code) => format!("panic_code=0x{:x}", code),
            None => "panic_code=<malformed>".to_string(),
        });
    }
    None
}

#[derive(Debug, Clone)]
pub struct TokenBalanceDelta {
    pub token: Address,
    pub initial: RU256,
    pub final_balance: RU256,
}

#[derive(Debug, Clone)]
pub struct ShadowSimulationReport {
    pub success: bool,
    pub profitable: bool,
    pub estimated_gas: u64,
    pub failed_step: Option<usize>,
    /// Gas used by the failing step (revert/halt). `None` when execution succeeded or no step ran.
    pub failure_gas_used: Option<u64>,
    /// Gas limit used for the failing step (revert/halt). `None` when execution succeeded or no step ran.
    pub failure_gas_limit: Option<u64>,
    /// Halt reason string for `ExecutionResult::Halt` failures (for example `OutOfGas`).
    pub halt_reason: Option<String>,
    pub initial_eth: RU256,
    pub final_eth: RU256,
    pub token_deltas: Vec<TokenBalanceDelta>,
    pub initial_value_wei: RU256,
    pub final_value_wei: RU256,
    pub gas_cost_wei: RU256,
    pub priced_tokens: usize,
    pub unpriced_tokens: usize,
    pub stale_priced_tokens: usize,
    pub error: Option<String>,
}

impl ShadowSimulationReport {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            profitable: false,
            estimated_gas: 0,
            failed_step: None,
            failure_gas_used: None,
            failure_gas_limit: None,
            halt_reason: None,
            initial_eth: RU256::ZERO,
            final_eth: RU256::ZERO,
            token_deltas: Vec::new(),
            initial_value_wei: RU256::ZERO,
            final_value_wei: RU256::ZERO,
            gas_cost_wei: RU256::ZERO,
            priced_tokens: 0,
            unpriced_tokens: 0,
            stale_priced_tokens: 0,
            error: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MarkToMarketProfitability {
    profitable: bool,
    initial_value_wei: RU256,
    final_value_wei: RU256,
    gas_cost_wei: RU256,
    priced_tokens: usize,
    unpriced_tokens: usize,
    stale_priced_tokens: usize,
}

fn parse_address_csv(raw: &str) -> Vec<Address> {
    raw.split(',')
        .filter_map(|token| {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                return None;
            }
            Address::from_str(trimmed).ok()
        })
        .collect()
}

fn load_profit_tracking_tokens() -> Vec<Address> {
    std::env::var("PROFIT_TRACK_TOKENS")
        .ok()
        .map(|raw| parse_address_csv(&raw))
        .unwrap_or_default()
}

fn merge_unique_tokens(base: &mut Vec<Address>, extras: impl IntoIterator<Item = Address>) {
    for token in extras {
        if !base.contains(&token) {
            base.push(token);
        }
    }
}

fn parse_address_value_csv<T, F>(raw: &str, parse_value: F) -> HashMap<Address, T>
where
    F: Fn(&str) -> Option<T>,
{
    raw.split(',')
        .filter_map(|item| {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (addr_raw, value_raw) = trimmed
                .split_once('=')
                .or_else(|| trimmed.split_once(':'))?;
            let address = Address::from_str(addr_raw.trim()).ok()?;
            let value = parse_value(value_raw.trim())?;
            Some((address, value))
        })
        .collect()
}

fn parse_u256_decimal(raw: &str) -> Option<RU256> {
    RU256::from_str(raw).ok()
}

fn load_profit_price_overrides_eth_wei() -> HashMap<Address, RU256> {
    std::env::var("PROFIT_TOKEN_PRICES_ETH_WEI")
        .ok()
        .map(|raw| parse_address_value_csv(&raw, parse_u256_decimal))
        .unwrap_or_default()
}

fn load_profit_token_price_age_overrides_ms() -> HashMap<Address, u64> {
    std::env::var("PROFIT_TOKEN_PRICE_AGE_MS")
        .ok()
        .map(|raw| parse_address_value_csv(&raw, |value| value.parse::<u64>().ok()))
        .unwrap_or_default()
}

fn load_profit_price_max_age_ms() -> u64 {
    std::env::var("PROFIT_PRICE_MAX_AGE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(120_000)
}

fn load_profit_base_price_age_ms() -> u64 {
    std::env::var("PROFIT_BASE_PRICE_AGE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn load_profit_decimal_overrides() -> HashMap<Address, u8> {
    std::env::var("PROFIT_TOKEN_DECIMALS")
        .ok()
        .map(|raw| {
            parse_address_value_csv(&raw, |value| {
                value.parse::<u8>().ok().filter(|decimals| *decimals <= 38)
            })
        })
        .unwrap_or_default()
}

fn load_profit_priority_fee_wei() -> RU256 {
    std::env::var("PROFIT_PRIORITY_FEE_WEI")
        .ok()
        .and_then(|value| parse_u256_decimal(value.trim()))
        .unwrap_or(RU256::ZERO)
}

fn load_profit_min_margin_wei() -> RU256 {
    std::env::var("PROFIT_MIN_MARGIN_WEI")
        .ok()
        .and_then(|value| parse_u256_decimal(value.trim()))
        .unwrap_or(RU256::ZERO)
}

fn call_bundle_enabled() -> bool {
    std::env::var("CALL_BUNDLE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn call_bundle_strict() -> bool {
    std::env::var("CALL_BUNDLE_STRICT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn call_bundle_timeout_ms() -> u64 {
    std::env::var("CALL_BUNDLE_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(100, 5_000))
        .unwrap_or(1_500)
}

fn call_bundle_relay_url() -> Option<String> {
    if let Ok(url) = std::env::var("CALL_BUNDLE_RELAY_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(url) = std::env::var("FLASHBOTS_RELAY_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(raw) = std::env::var("BUILDER_URLS") {
        for token in raw.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("flashbots") || trimmed.contains("relay") {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallBundleVerdict {
    Skipped,
    Passed,
    Failed,
}

pub async fn verify_call_bundle_preflight(
    bundle_txs: &[String],
    target_block: u64,
    max_timestamp: u64,
) -> anyhow::Result<CallBundleVerdict> {
    if !call_bundle_enabled() || bundle_txs.is_empty() {
        return Ok(CallBundleVerdict::Skipped);
    }

    let Some(relay_url) = call_bundle_relay_url() else {
        if call_bundle_strict() {
            anyhow::bail!("callBundle strict mode enabled but no relay URL configured");
        }
        return Ok(CallBundleVerdict::Skipped);
    };

    let timeout_ms = call_bundle_timeout_ms();
    let block_tag = format!("0x{target_block:x}");
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_callBundle",
        "params": [{
            "txs": bundle_txs,
            "blockNumber": block_tag,
            "stateBlockNumber": "latest",
            "timestamp": max_timestamp
        }]
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let response = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        client.post(&relay_url).json(&payload).send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("eth_callBundle request timed out after {}ms", timeout_ms))??;
    let body = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        response.json::<serde_json::Value>(),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "eth_callBundle response decode timed out after {}ms",
            timeout_ms
        )
    })??;

    if let Some(err_obj) = body.get("error") {
        let msg = err_obj
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown callBundle error");
        anyhow::bail!("eth_callBundle rejected: {}", msg);
    }
    if body.get("result").is_none() {
        anyhow::bail!("eth_callBundle malformed response: missing `result`");
    }
    Ok(CallBundleVerdict::Passed)
}

pub async fn dynamic_gas_escrow_sufficient(
    provider: &alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
    vault: Address,
    gas_limit: u64,
    additional_required_wei: RU256,
) -> anyhow::Result<(bool, RU256, RU256)> {
    let timeout_ms = std::env::var("DYNAMIC_GAS_ESCROW_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(100, 3_000))
        .unwrap_or(1_250);
    let gas_price =
        tokio::time::timeout(Duration::from_millis(timeout_ms), provider.get_gas_price())
            .await
            .map_err(|_| anyhow::anyhow!("dynamic gas escrow gas-price probe timed out"))??;
    let vault_balance = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        provider.get_balance(vault),
    )
    .await
    .map_err(|_| anyhow::anyhow!("dynamic gas escrow balance probe timed out"))??;

    let gas_price_revm = RU256::from(gas_price);
    let vault_balance_revm = RU256::from_be_bytes(vault_balance.to_be_bytes::<32>());
    let required_budget =
        dynamic_escrow_required_budget(gas_price_revm, gas_limit, additional_required_wei);
    Ok((
        vault_balance_revm >= required_budget,
        vault_balance_revm,
        required_budget,
    ))
}

fn dynamic_escrow_required_budget(
    gas_price_wei: RU256,
    gas_limit: u64,
    additional_required_wei: RU256,
) -> RU256 {
    gas_price_wei
        .saturating_mul(RU256::from(gas_limit))
        .saturating_add(additional_required_wei)
}

fn stable_token_eth_price_wei() -> RU256 {
    if let Some(explicit_price) = std::env::var("PROFIT_STABLE_TOKEN_ETH_WEI")
        .ok()
        .and_then(|value| parse_u256_decimal(value.trim()))
    {
        return explicit_price;
    }
    let eth_usd = std::env::var("PROFIT_ETH_USD")
        .ok()
        .and_then(|value| value.trim().parse::<u128>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(3_000);
    RU256::from(1_000_000_000_000_000_000u128 / eth_usd)
}

fn token_decimals(
    token: Address,
    chain_config: &crate::config::chains::ChainConfig,
    decimal_overrides: &HashMap<Address, u8>,
) -> u8 {
    if let Some(decimals) = decimal_overrides.get(&token) {
        return *decimals;
    }
    if token == chain_config.usdc || chain_config.stablecoins.contains(&token) {
        6
    } else {
        18
    }
}

fn token_price_eth_wei(
    token: Address,
    chain_config: &crate::config::chains::ChainConfig,
    stable_price_eth_wei: RU256,
    price_overrides: &HashMap<Address, RU256>,
) -> Option<(RU256, &'static str)> {
    if let Some(price) = price_overrides.get(&token) {
        return Some((*price, "override"));
    }
    if token == chain_config.weth {
        return Some((RU256::from(1_000_000_000_000_000_000u128), "weth_parity"));
    }
    if token == chain_config.usdc || chain_config.stablecoins.contains(&token) {
        return Some((stable_price_eth_wei, "stable_proxy"));
    }
    None
}

fn pow10_u256(exp: u8) -> RU256 {
    let mut out = RU256::from(1u64);
    for _ in 0..exp {
        out = out.saturating_mul(RU256::from(10u64));
    }
    out
}

fn token_value_eth_wei(balance: RU256, price_eth_wei: RU256, decimals: u8) -> RU256 {
    if decimals == 0 {
        return balance.saturating_mul(price_eth_wei);
    }
    let scale = pow10_u256(decimals);
    if scale.is_zero() {
        return RU256::ZERO;
    }
    balance.saturating_mul(price_eth_wei) / scale
}

fn mark_to_market_profitability(
    chain_config: &crate::config::chains::ChainConfig,
    initial_eth: RU256,
    final_eth: RU256,
    token_deltas: &[TokenBalanceDelta],
    estimated_gas: u64,
    observed_base_fee_wei: RU256,
) -> MarkToMarketProfitability {
    let price_overrides = load_profit_price_overrides_eth_wei();
    let price_age_overrides = load_profit_token_price_age_overrides_ms();
    let decimal_overrides = load_profit_decimal_overrides();
    let stable_price_eth_wei = stable_token_eth_price_wei();
    let max_price_age_ms = load_profit_price_max_age_ms();
    let base_price_age_ms = load_profit_base_price_age_ms();

    let mut initial_value_wei = initial_eth;
    let mut final_value_wei = final_eth;
    let mut priced_tokens = 0usize;
    let mut unpriced_tokens = 0usize;
    let mut stale_priced_tokens = 0usize;

    for delta in token_deltas {
        if let Some((price_eth_wei, _source)) = token_price_eth_wei(
            delta.token,
            chain_config,
            stable_price_eth_wei,
            &price_overrides,
        ) {
            let decimals = token_decimals(delta.token, chain_config, &decimal_overrides);
            let initial_token_value = token_value_eth_wei(delta.initial, price_eth_wei, decimals);
            let final_token_value =
                token_value_eth_wei(delta.final_balance, price_eth_wei, decimals);
            initial_value_wei = initial_value_wei.saturating_add(initial_token_value);
            final_value_wei = final_value_wei.saturating_add(final_token_value);
            priced_tokens = priced_tokens.saturating_add(1);
            let age_ms = price_age_overrides
                .get(&delta.token)
                .copied()
                .unwrap_or(base_price_age_ms);
            if age_ms > max_price_age_ms {
                stale_priced_tokens = stale_priced_tokens.saturating_add(1);
            }
        } else {
            unpriced_tokens = unpriced_tokens.saturating_add(1);
        }
    }

    let gas_price_wei = observed_base_fee_wei.saturating_add(load_profit_priority_fee_wei());
    let gas_cost_wei = gas_price_wei.saturating_mul(RU256::from(estimated_gas));
    let min_margin_wei = load_profit_min_margin_wei();
    let required_final_wei = initial_value_wei
        .saturating_add(gas_cost_wei)
        .saturating_add(min_margin_wei);
    let profitable = final_value_wei > required_final_wei;

    MarkToMarketProfitability {
        profitable,
        initial_value_wei,
        final_value_wei,
        gas_cost_wei,
        priced_tokens,
        unpriced_tokens,
        stale_priced_tokens,
    }
}

pub fn estimate_dumpable_token_gain_eth_wei(
    chain_id: u64,
    token_deltas: &[TokenBalanceDelta],
) -> Option<RU256> {
    let chain_config = crate::config::chains::ChainConfig::get(chain_id);
    let price_overrides = load_profit_price_overrides_eth_wei();
    let decimal_overrides = load_profit_decimal_overrides();
    let stable_price_eth_wei = stable_token_eth_price_wei();
    let mut total_gain_wei = RU256::ZERO;

    for delta in token_deltas {
        if delta.token == chain_config.weth || delta.final_balance <= delta.initial {
            continue;
        }
        let gain = delta.final_balance.saturating_sub(delta.initial);
        if gain.is_zero() {
            continue;
        }
        let (price_eth_wei, _) = token_price_eth_wei(
            delta.token,
            &chain_config,
            stable_price_eth_wei,
            &price_overrides,
        )?;
        let decimals = token_decimals(delta.token, &chain_config, &decimal_overrides);
        let value_wei = token_value_eth_wei(gain, price_eth_wei, decimals);
        total_gain_wei = total_gain_wei.saturating_add(value_wei);
    }

    Some(total_gain_wei)
}

pub fn replay_path(
    rpc_url: &str,
    chain_id: u64,
    attacker: Address,
    params: &ExploitParams,
) -> ShadowSimulationReport {
    replay_path_at_block_with_env(rpc_url, chain_id, attacker, params, None, None)
}

pub fn replay_path_at_block(
    rpc_url: &str,
    chain_id: u64,
    attacker: Address,
    params: &ExploitParams,
    pinned_block: Option<u64>,
) -> ShadowSimulationReport {
    replay_path_at_block_with_env(rpc_url, chain_id, attacker, params, pinned_block, None)
}

pub fn replay_path_with_env(
    rpc_url: &str,
    chain_id: u64,
    attacker: Address,
    params: &ExploitParams,
    env_block_number: Option<u64>,
) -> ShadowSimulationReport {
    replay_path_at_block_with_env(rpc_url, chain_id, attacker, params, None, env_block_number)
}

pub fn replay_path_at_block_with_env(
    rpc_url: &str,
    chain_id: u64,
    attacker: Address,
    params: &ExploitParams,
    pinned_block: Option<u64>,
    env_block_number: Option<u64>,
) -> ShadowSimulationReport {
    if tokio::runtime::Handle::try_current().is_err() {
        return ShadowSimulationReport::failed(
            "shadow verifier requires a Tokio runtime for fork-db operations",
        );
    }

    let fork_db = if let Some(block_number) = pinned_block {
        ForkDB::with_block_number(rpc_url, block_number)
    } else {
        ForkDB::new(rpc_url)
    };
    let fork_db = match fork_db {
        Ok(db) => db,
        Err(err) => {
            return ShadowSimulationReport::failed(format!(
                "shadow verifier fork-db initialization failed: {err}"
            ));
        }
    };
    let mut cache_db = CacheDB::new(fork_db);
    let attacker_r = RAddress::from_slice(attacker.as_slice());

    let chain_config = crate::config::chains::ChainConfig::get(chain_id);
    let mut tracked_tokens = chain_config.known_tokens.clone();
    merge_unique_tokens(&mut tracked_tokens, chain_config.stablecoins.clone());
    merge_unique_tokens(&mut tracked_tokens, load_profit_tracking_tokens());
    let initial_eth = match read_eth_balance(&mut cache_db, attacker_r) {
        Ok(value) => value,
        Err(err) => {
            return ShadowSimulationReport::failed(format!(
                "shadow verifier failed to read initial ETH balance: {err}"
            ));
        }
    };
    let initial_tokens = match tracked_tokens
        .iter()
        .map(|token| {
            read_token_balance(&mut cache_db, *token, attacker).map(|balance| (*token, balance))
        })
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(tokens) => tokens,
        Err(err) => {
            return ShadowSimulationReport::failed(format!(
                "shadow verifier failed to read initial token balances: {err}"
            ));
        }
    };

    if let Err(err) = apply_mock_flash_loan(&mut cache_db, attacker, params) {
        return ShadowSimulationReport::failed(format!(
            "shadow verifier flash-loan mock failed: {err}"
        ));
    }

    let mb_executor = MultiBlockExecutor::new(&params.steps, params.block_offsets.as_deref());
    let mut estimated_gas = 0u64;
    let mut failed_step = None;
    let mut failure_gas_used = None;
    let mut failure_gas_limit = None;
    let mut halt_reason = None;
    let mut failure_error = None;
    let observed_base_fee_wei;

    {
        let mut evm = Evm::builder()
            .with_db(&mut cache_db)
            .modify_tx_env(|tx| {
                tx.caller = attacker_r;
            })
            .build();
        observed_base_fee_wei = evm.context.evm.env.block.basefee;

        let mut block_number = u256_to_u64(evm.context.evm.env.block.number);
        let mut block_timestamp = u256_to_u64(evm.context.evm.env.block.timestamp);
        let block_time = block_time_for_chain(chain_id);
        let mut current_offset = 0u64;

        // Model the intended execution block env explicitly when requested.
        // State pinning uses `ForkDB::with_block_number`, but the block env for the *next* block
        // is often what matters for `block.number`/`block.timestamp` guards.
        if let Some(state_block) = pinned_block {
            block_number = state_block;
            evm.context.evm.env.block.number = RU256::from(block_number);
        }
        if let Some(env_block) = env_block_number {
            // Best-effort timestamp advance to keep monotonic env, without extra RPC.
            if env_block > block_number {
                let delta = env_block.saturating_sub(block_number);
                for _ in 0..delta {
                    advance_block_env(&mut block_number, &mut block_timestamp, block_time);
                }
            } else {
                block_number = env_block;
            }
            evm.context.evm.env.block.number = RU256::from(block_number);
            evm.context.evm.env.block.timestamp = RU256::from(block_timestamp);
        }

        let grouped_steps = mb_executor.grouped_steps();
        let mut step_idx = 0usize;

        for (offset, steps) in grouped_steps {
            if offset > current_offset {
                for _ in current_offset..offset {
                    advance_block_env(&mut block_number, &mut block_timestamp, block_time);
                }
                current_offset = offset;
                evm.context.evm.env.block.number = RU256::from(block_number);
                evm.context.evm.env.block.timestamp = RU256::from(block_timestamp);
            }

            for block_step in steps {
                let step = &block_step.step;
                let step_gas_limit = 2_000_000u64;
                evm.context.evm.env.tx.transact_to =
                    TransactTo::Call(RAddress::from_slice(step.target.as_slice()));
                evm.context.evm.env.tx.data = step.call_data.clone();
                evm.context.evm.env.tx.gas_limit = step_gas_limit;

                match evm.transact_commit() {
                    Ok(ExecutionResult::Success { gas_used, .. }) => {
                        estimated_gas = estimated_gas.saturating_add(gas_used);
                    }
                    Ok(ExecutionResult::Revert { gas_used, output }) => {
                        failed_step = Some(step_idx);
                        failure_gas_used = Some(gas_used);
                        failure_gas_limit = Some(step_gas_limit);
                        estimated_gas = estimated_gas.saturating_add(gas_used);
                        if let Some(reason) = decode_revert_reason(output.as_ref()) {
                            failure_error = Some(format!("revert: {reason}"));
                        } else {
                            failure_error =
                                Some(format!("revert: 0x{}", hex::encode(output.as_ref())));
                        }
                        break;
                    }
                    Ok(ExecutionResult::Halt { reason, gas_used }) => {
                        failed_step = Some(step_idx);
                        failure_gas_used = Some(gas_used);
                        failure_gas_limit = Some(step_gas_limit);
                        estimated_gas = estimated_gas.saturating_add(gas_used);
                        let rendered = format!("{reason:?}");
                        halt_reason = Some(rendered.clone());
                        failure_error = Some(format!("halt: {rendered}"));
                        break;
                    }
                    Err(err) => {
                        failed_step = Some(step_idx);
                        failure_error = Some(format!("revm transact error: {err:?}"));
                        break;
                    }
                }
                step_idx = step_idx.saturating_add(1);
            }

            if failed_step.is_some() {
                break;
            }
        }
    }

    let final_eth = match read_eth_balance(&mut cache_db, attacker_r) {
        Ok(value) => value,
        Err(err) => {
            return ShadowSimulationReport::failed(format!(
                "shadow verifier failed to read final ETH balance: {err}"
            ));
        }
    };
    let final_tokens = match tracked_tokens
        .iter()
        .map(|token| {
            read_token_balance(&mut cache_db, *token, attacker).map(|balance| (*token, balance))
        })
        .collect::<anyhow::Result<Vec<_>>>()
    {
        Ok(tokens) => tokens,
        Err(err) => {
            return ShadowSimulationReport::failed(format!(
                "shadow verifier failed to read final token balances: {err}"
            ));
        }
    };

    let token_deltas = initial_tokens
        .iter()
        .map(|(token, initial)| {
            let final_balance = final_tokens
                .iter()
                .find_map(|(t, balance)| if t == token { Some(*balance) } else { None })
                .unwrap_or(RU256::ZERO);
            TokenBalanceDelta {
                token: *token,
                initial: *initial,
                final_balance,
            }
        })
        .collect::<Vec<_>>();

    let mtm_report = mark_to_market_profitability(
        &chain_config,
        initial_eth,
        final_eth,
        &token_deltas,
        estimated_gas,
        observed_base_fee_wei,
    );
    let success = failed_step.is_none();

    ShadowSimulationReport {
        success,
        profitable: mtm_report.profitable,
        estimated_gas,
        failed_step,
        failure_gas_used,
        failure_gas_limit,
        halt_reason,
        initial_eth,
        final_eth,
        token_deltas,
        initial_value_wei: mtm_report.initial_value_wei,
        final_value_wei: mtm_report.final_value_wei,
        gas_cost_wei: mtm_report.gas_cost_wei,
        priced_tokens: mtm_report.priced_tokens,
        unpriced_tokens: mtm_report.unpriced_tokens,
        stale_priced_tokens: mtm_report.stale_priced_tokens,
        error: failure_error,
    }
}

/// Legacy helper kept for anchor compatibility.
/// Runtime replay profitability uses mark-to-market valuation in `replay_path`.
pub fn is_profitable(
    initial_eth: RU256,
    final_eth: RU256,
    token_deltas: &[TokenBalanceDelta],
) -> bool {
    if final_eth > initial_eth {
        return true;
    }
    token_deltas
        .iter()
        .any(|delta| delta.final_balance > delta.initial)
}

fn read_eth_balance(db: &mut CacheDB<ForkDB>, owner: RAddress) -> anyhow::Result<RU256> {
    let account = db
        .basic(owner)
        .map_err(|err| anyhow!("failed to read account info for {owner:?}: {err}"))?;
    Ok(account.map(|acc| acc.balance).unwrap_or_default())
}

fn read_token_balance<DB: DatabaseRef>(
    db: &mut CacheDB<DB>,
    token: Address,
    owner: Address,
) -> anyhow::Result<RU256> {
    let token_r = RAddress::from_slice(token.as_slice());
    let slot = erc20_balance_slot(owner);
    db.storage(token_r, slot)
        .map_err(|_| anyhow!("failed to read token storage for {token:?} owner {owner:?}"))
}

fn apply_mock_flash_loan(
    db: &mut CacheDB<ForkDB>,
    attacker: Address,
    params: &ExploitParams,
) -> anyhow::Result<()> {
    if !params.flash_loan_legs.is_empty() {
        for leg in &params.flash_loan_legs {
            if leg.amount.is_zero() {
                continue;
            }
            let amount = alloy_to_revm_u256(leg.amount);
            if leg.token == Address::ZERO {
                let attacker_r = RAddress::from_slice(attacker.as_slice());
                let mut info = db.basic(attacker_r)?.unwrap_or_else(AccountInfo::default);
                info.balance = info.balance.saturating_add(amount);
                db.insert_account_info(attacker_r, info);
                continue;
            }

            let token_r = RAddress::from_slice(leg.token.as_slice());
            let slot = erc20_balance_slot(attacker);
            let current = db.storage(token_r, slot)?;
            let updated = current.saturating_add(amount);
            db.insert_account_storage(token_r, slot, updated)?;
        }
        return Ok(());
    }

    if params.flash_loan_amount.is_zero() {
        return Ok(());
    }

    let amount = alloy_to_revm_u256(params.flash_loan_amount);
    if params.flash_loan_token == Address::ZERO {
        let attacker_r = RAddress::from_slice(attacker.as_slice());
        let mut info = db.basic(attacker_r)?.unwrap_or_else(AccountInfo::default);
        info.balance = info.balance.saturating_add(amount);
        db.insert_account_info(attacker_r, info);
        return Ok(());
    }

    let token_r = RAddress::from_slice(params.flash_loan_token.as_slice());
    let slot = erc20_balance_slot(attacker);
    let current = db.storage(token_r, slot)?;
    let updated = current.saturating_add(amount);
    db.insert_account_storage(token_r, slot, updated)?;
    Ok(())
}

fn erc20_balance_slot(owner: Address) -> RU256 {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(owner.as_slice());
    let slot_hash = keccak256(input);
    RU256::from_be_bytes(slot_hash.0)
}

fn alloy_to_revm_u256(value: alloy::primitives::U256) -> RU256 {
    RU256::from_be_bytes(value.to_be_bytes::<32>())
}

fn u256_to_u64(value: RU256) -> u64 {
    let bytes = value.to_be_bytes::<32>();
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&bytes[24..32]);
    u64::from_be_bytes(tail)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_revert_reason, dynamic_escrow_required_budget, erc20_balance_slot,
        estimate_dumpable_token_gain_eth_wei, mark_to_market_profitability, parse_address_csv,
        token_value_eth_wei, TokenBalanceDelta,
    };
    use alloy::primitives::{address, Address};
    use revm::primitives::U256 as RU256;

    #[test]
    fn test_mark_to_market_uses_gas_adjusted_eth_delta() {
        let chain = crate::config::chains::ChainConfig::base();
        let report = mark_to_market_profitability(
            &chain,
            RU256::from(1_000_000_000_000_000_000u128),
            RU256::from(1_001_000_000_000_000_000u128),
            &[],
            100_000,
            RU256::from(1_000_000_000u64),
        );
        assert!(report.profitable);
    }

    #[test]
    fn test_mark_to_market_rejects_unpriced_token_gain() {
        let chain = crate::config::chains::ChainConfig::base();
        let token = Address::from([0x11; 20]); // Unknown by default
        let deltas = vec![TokenBalanceDelta {
            token,
            initial: RU256::from(5u64),
            final_balance: RU256::from(9u64),
        }];
        let report = mark_to_market_profitability(
            &chain,
            RU256::from(10u64),
            RU256::from(10u64),
            &deltas,
            0,
            RU256::ZERO,
        );
        assert!(!report.profitable);
        assert_eq!(report.unpriced_tokens, 1);
    }

    #[test]
    fn test_estimate_dumpable_token_gain_eth_wei_uses_stable_proxy_price() {
        let chain = crate::config::chains::ChainConfig::base();
        let deltas = vec![
            TokenBalanceDelta {
                token: chain.weth,
                initial: RU256::from(1_000u64),
                final_balance: RU256::from(2_000u64),
            },
            TokenBalanceDelta {
                token: chain.usdc,
                initial: RU256::from(10_000_000u64),
                final_balance: RU256::from(20_000_000u64),
            },
        ];

        let gain = estimate_dumpable_token_gain_eth_wei(chain.chain_id, &deltas)
            .expect("stablecoin gain should be priceable via stable proxy");
        assert!(gain > RU256::ZERO);
    }

    #[test]
    fn test_estimate_dumpable_token_gain_eth_wei_fail_closed_on_unpriced_token() {
        let chain = crate::config::chains::ChainConfig::base();
        let unknown = Address::from([0x77; 20]);
        let deltas = vec![TokenBalanceDelta {
            token: unknown,
            initial: RU256::from(1u64),
            final_balance: RU256::from(9u64),
        }];
        let gain = estimate_dumpable_token_gain_eth_wei(chain.chain_id, &deltas);
        assert!(
            gain.is_none(),
            "unpriced dumpable token gains must fail closed"
        );
    }

    #[test]
    fn test_token_value_eth_wei_scales_with_decimals() {
        let one_usdc_raw = RU256::from(1_000_000u64);
        let usdc_price_eth = RU256::from(500_000_000_000_000u64); // 0.0005 ETH
        let value = token_value_eth_wei(one_usdc_raw, usdc_price_eth, 6);
        assert_eq!(value, usdc_price_eth);
    }

    #[test]
    fn test_erc20_balance_slot_matches_known_keccak_layout() {
        let owner = address!("0000000000000000000000000000000000001337");
        let slot = erc20_balance_slot(owner);
        assert_ne!(slot, RU256::ZERO);
    }

    #[test]
    fn test_parse_address_csv_ignores_invalid_items() {
        let parsed = parse_address_csv(
            "0x4200000000000000000000000000000000000006,not-an-address,0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        );
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_decode_revert_reason_panic_malformed_is_not_zero_default() {
        let mut payload = vec![0x4e, 0x48, 0x7b, 0x71];
        // 32-byte word with non-zero high bytes (invalid for usize downcast helper)
        payload.extend_from_slice(&[0x01; 32]);
        let decoded = decode_revert_reason(&payload);
        assert_eq!(decoded.as_deref(), Some("panic_code=<malformed>"));
    }

    #[test]
    fn test_decode_revert_reason_panic_valid_word_decodes_hex_code() {
        let mut payload = vec![0x4e, 0x48, 0x7b, 0x71];
        let mut word = [0u8; 32];
        word[31] = 0x11;
        payload.extend_from_slice(&word);
        let decoded = decode_revert_reason(&payload);
        assert_eq!(decoded.as_deref(), Some("panic_code=0x11"));
    }

    #[test]
    fn test_dynamic_escrow_required_budget_includes_additional_value() {
        let gas_price = RU256::from(2_000_000_000u64);
        let gas_limit = 200_000u64;
        let additional = RU256::from(3_000_000_000_000_000u128);
        let required = dynamic_escrow_required_budget(gas_price, gas_limit, additional);
        let expected = gas_price
            .saturating_mul(RU256::from(gas_limit))
            .saturating_add(additional);
        assert_eq!(required, expected);
    }
}
