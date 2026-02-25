use alloy::providers::Provider;
use alloy::providers::RootProvider;
use alloy::rpc::types::eth::{AccessList, AccessListResult, TransactionRequest};
use alloy::transports::http::Http;
use reqwest::Client;

const DEFAULT_ACCESS_LIST_TIMEOUT_MS: u64 = 75;
const DEFAULT_ACCESS_LIST_TOTAL_BUDGET_MS: u64 = 200;
const DEFAULT_ACCESS_LIST_MAX_TXS_PER_GROUP: usize = 4;
const DEFAULT_ACCESS_LIST_MAX_ITEMS: usize = 96;
const DEFAULT_ACCESS_LIST_MAX_KEYS_PER_ITEM: usize = 64;

pub fn access_list_enabled() -> bool {
    std::env::var("ACCESS_LIST_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

pub fn access_list_strict_enabled() -> bool {
    std::env::var("ACCESS_LIST_STRICT")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_timeout_ms() -> u64 {
    std::env::var("ACCESS_LIST_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(10, 500))
        .unwrap_or(DEFAULT_ACCESS_LIST_TIMEOUT_MS)
}

fn load_total_budget_ms() -> u64 {
    std::env::var("ACCESS_LIST_TOTAL_BUDGET_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(10, 2_000))
        .unwrap_or(DEFAULT_ACCESS_LIST_TOTAL_BUDGET_MS)
}

fn load_max_txs_per_group() -> usize {
    std::env::var("ACCESS_LIST_MAX_TXS_PER_GROUP")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, 32))
        .unwrap_or(DEFAULT_ACCESS_LIST_MAX_TXS_PER_GROUP)
}

fn load_max_items() -> usize {
    std::env::var("ACCESS_LIST_MAX_ITEMS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, 1_024))
        .unwrap_or(DEFAULT_ACCESS_LIST_MAX_ITEMS)
}

fn load_max_keys_per_item() -> usize {
    std::env::var("ACCESS_LIST_MAX_KEYS_PER_ITEM")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, 1_024))
        .unwrap_or(DEFAULT_ACCESS_LIST_MAX_KEYS_PER_ITEM)
}

fn clamp_access_list_result(mut result: AccessListResult) -> AccessList {
    let max_items = load_max_items();
    let max_keys = load_max_keys_per_item();
    if result.access_list.0.len() > max_items {
        result.access_list.0.truncate(max_items);
    }
    for item in result.access_list.0.iter_mut() {
        if item.storage_keys.len() > max_keys {
            item.storage_keys.truncate(max_keys);
        }
    }
    result.access_list
}

#[derive(Debug, Clone, Copy)]
pub struct AccessListBudget {
    started_ms: u64,
}

impl AccessListBudget {
    pub fn start(now_ms: u64) -> Self {
        Self { started_ms: now_ms }
    }

    pub fn exhausted(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.started_ms) > load_total_budget_ms()
    }
}

pub fn max_txs_per_group() -> usize {
    load_max_txs_per_group()
}

/// Best-effort: attaches an EIP-2930 access list using `eth_createAccessList(pending)` under a hard timeout.
/// Returns `Ok(true)` if an access list was attached, `Ok(false)` if skipped/empty, `Err(_)` if strict mode should fail-closed.
pub async fn maybe_attach_access_list_best_effort(
    provider: &RootProvider<Http<Client>>,
    tx_request: &mut TransactionRequest,
    budget: &AccessListBudget,
    now_ms: u64,
) -> anyhow::Result<bool> {
    if !access_list_enabled() {
        return Ok(false);
    }
    if budget.exhausted(now_ms) {
        return Ok(false);
    }
    if tx_request.access_list.is_some() {
        return Ok(false);
    }
    let timeout_ms = load_timeout_ms();
    let fut = provider.create_access_list(tx_request).pending();
    let result = match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await
    {
        Ok(Ok(res)) => res,
        Ok(Err(err)) => {
            if access_list_strict_enabled() {
                return Err(anyhow::anyhow!("eth_createAccessList failed: {err}"));
            }
            return Ok(false);
        }
        Err(_) => {
            if access_list_strict_enabled() {
                return Err(anyhow::anyhow!(
                    "eth_createAccessList timed out after {timeout_ms}ms"
                ));
            }
            return Ok(false);
        }
    };

    let access_list = clamp_access_list_result(result);
    if access_list.is_empty() {
        return Ok(false);
    }
    tx_request.access_list = Some(access_list);
    Ok(true)
}
