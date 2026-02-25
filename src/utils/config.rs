use crate::error::{InvariantWaitError, Result};
use alloy::primitives::U256;
use std::env;

pub struct Config {
    pub eth_rpc_url: String,
    pub execution_rpc_url: Option<String>,
    pub eth_ws_url: String,
    pub eth_private_key: Option<String>,
    pub stealth_vault_min_balance_wei: Option<String>,
    pub flashbots_relay_url: Option<String>,
    pub builder_urls: Vec<String>,
    pub submission_enabled: bool,
    pub chain_id: u64,
    pub scan_min_tvl_usd: u128,
    pub war_mode: bool,
}

#[derive(Debug, Clone)]
pub struct StrategyParams {
    pub min_expected_profit_wei: U256,
    pub objective_allowlist: Option<String>,
    pub objective_denylist: Option<String>,
    pub objective_max_per_target: Option<usize>,
}

impl StrategyParams {
    pub fn from_env() -> Self {
        let min_expected_profit_wei = env::var("MIN_EXPECTED_PROFIT_WEI")
            .ok()
            .and_then(|raw| raw.trim().parse::<U256>().ok())
            .unwrap_or(U256::ZERO);
        let objective_allowlist = env::var("OBJECTIVE_ALLOWLIST")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let objective_denylist = env::var("OBJECTIVE_DENYLIST")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let objective_max_per_target = env::var("OBJECTIVE_MAX_PER_TARGET")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok());
        Self {
            min_expected_profit_wei,
            objective_allowlist,
            objective_denylist,
            objective_max_per_target,
        }
    }
}

fn validate_http_url(name: &str, raw: &str) -> Result<()> {
    let parsed = raw.parse::<reqwest::Url>().map_err(|e| {
        InvariantWaitError::InvalidConfig(format!("{name} must be a valid URL, got `{raw}`: {e}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        other => Err(InvariantWaitError::InvalidConfig(format!(
            "{name} must use http(s) scheme, got `{other}`"
        ))
        .into()),
    }
}

fn validate_ws_url(name: &str, raw: &str) -> Result<()> {
    let parsed = raw.parse::<reqwest::Url>().map_err(|e| {
        InvariantWaitError::InvalidConfig(format!("{name} must be a valid URL, got `{raw}`: {e}"))
    })?;
    match parsed.scheme() {
        "ws" | "wss" => Ok(()),
        other => Err(InvariantWaitError::InvalidConfig(format!(
            "{name} must use ws(s) scheme, got `{other}`"
        ))
        .into()),
    }
}

fn normalize_builder_url_for_validation(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("grpc://") {
        return Some(format!("http://{rest}"));
    }
    if let Some(rest) = trimmed.strip_prefix("grpcs://") {
        return Some(format!("https://{rest}"));
    }
    Some(trimmed.to_string())
}

impl Config {
    pub fn load() -> Result<Self> {
        let submission_mode_requested =
            env::var("TX_SUBMISSION_ENABLED").unwrap_or_else(|_| "false".to_string()) == "true";
        if submission_mode_requested {
            return Err(InvariantWaitError::InvalidConfig(
                "TX_SUBMISSION_ENABLED is not supported in this build. Dark Solver runs in simulation-only mode."
                    .to_string(),
            )
            .into());
        }
        let submission_enabled = false;

        let eth_rpc_url = env::var("ETH_RPC_URL").map_err(|_| {
            InvariantWaitError::MissingConfig("ETH_RPC_URL must be set".to_string())
        })?;
        validate_http_url("ETH_RPC_URL", &eth_rpc_url)?;
        let execution_rpc_url = env::var("EXECUTION_RPC_URL").ok();
        if let Some(url) = execution_rpc_url.as_deref() {
            validate_http_url("EXECUTION_RPC_URL", url)?;
        }

        let eth_ws_url = env::var("ETH_WS_URL")
            .map_err(|_| InvariantWaitError::MissingConfig("ETH_WS_URL must be set".to_string()))?;
        validate_ws_url("ETH_WS_URL", &eth_ws_url)?;

        // Prefer the dedicated vault key when provided so submission identity is explicit and stable.
        let stealth_vault_private_key = env::var("STEALTH_VAULT_PRIVATE_KEY").ok();
        let eth_private_key =
            stealth_vault_private_key.or_else(|| env::var("ETH_PRIVATE_KEY").ok());
        let stealth_vault_min_balance_wei = env::var("STEALTH_VAULT_MIN_BALANCE_WEI").ok();
        let flashbots_relay_url = env::var("FLASHBOTS_RELAY_URL").ok();
        if let Some(url) = flashbots_relay_url.as_deref() {
            validate_http_url("FLASHBOTS_RELAY_URL", url)?;
            if submission_enabled {
                let scheme = url
                    .parse::<reqwest::Url>()
                    .ok()
                    .map(|u| u.scheme().to_string())
                    .unwrap_or_default();
                if scheme != "https" {
                    return Err(InvariantWaitError::InvalidConfig(
                        "FLASHBOTS_RELAY_URL must use https in TX_SUBMISSION_ENABLED=true".to_string(),
                    )
                    .into());
                }
            }
        }

        // Builder URLs: comma-separated list of direct builder RPC endpoints
        let builder_urls: Vec<String> = env::var("BUILDER_URLS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for raw in &builder_urls {
            let Some(normalized) = normalize_builder_url_for_validation(raw) else {
                continue;
            };
            validate_http_url("BUILDER_URLS entry", &normalized)?;
            if submission_enabled {
                // Force TLS when private submission is enabled; plaintext endpoints leak bundles.
                let parsed = normalized.parse::<reqwest::Url>().map_err(|e| {
                    InvariantWaitError::InvalidConfig(format!(
                        "BUILDER_URLS entry must be a valid URL, got `{raw}`: {e}"
                    ))
                })?;
                if parsed.scheme() != "https" {
                    return Err(InvariantWaitError::InvalidConfig(format!(
                        "BUILDER_URLS entry must use https (or grpcs://), got `{raw}`"
                    ))
                    .into());
                }
            }
        }

        let chain_id_raw = env::var("CHAIN_ID")
            .map_err(|_| InvariantWaitError::MissingConfig("CHAIN_ID must be set".to_string()))?;
        let chain_id = chain_id_raw.parse::<u64>().map_err(|_| {
            InvariantWaitError::InvalidConfig(format!(
                "CHAIN_ID must be a valid u64, got `{chain_id_raw}`"
            ))
        })?;

        let has_chain_default_builders =
            !crate::config::chains::ChainConfig::default_private_builder_urls(chain_id).is_empty();

        if submission_enabled {
            if eth_private_key.is_none() {
                return Err(InvariantWaitError::MissingConfig(
                    "TX_SUBMISSION_ENABLED is enabled but ETH_PRIVATE_KEY is missing".to_string(),
                )
                .into());
            }
            // Early sanity check: prevent accidental non-hex secrets. Actual parsing happens in the executor.
            if let Some(pk) = eth_private_key.as_deref() {
                let trimmed = pk.trim().trim_start_matches("0x");
                let hexish = !trimmed.is_empty()
                    && trimmed.len() % 2 == 0
                    && trimmed.as_bytes().iter().all(|b| b.is_ascii_hexdigit());
                if !hexish {
                    return Err(InvariantWaitError::InvalidConfig(
                        "ETH_PRIVATE_KEY must be hex (optionally 0x-prefixed)".to_string(),
                    )
                    .into());
                }
            }
            if flashbots_relay_url.is_none()
                && builder_urls.is_empty()
                && !has_chain_default_builders
            {
                return Err(InvariantWaitError::MissingConfig(
                    "TX_SUBMISSION_ENABLED is enabled but no private builders are configured for this chain (set FLASHBOTS_RELAY_URL or BUILDER_URLS)"
                        .to_string(),
                )
                .into());
            }
        }

        Ok(Self {
            eth_rpc_url,
            execution_rpc_url,
            eth_ws_url,
            eth_private_key,
            stealth_vault_min_balance_wei,
            flashbots_relay_url,
            builder_urls,
            submission_enabled,
            chain_id,
            scan_min_tvl_usd: env::var("SCAN_MIN_TVL_USD")
                .ok()
                .and_then(|v| v.trim().parse::<u128>().ok())
                .unwrap_or(50_000), // Default minimum TVL floor (USD) for target discovery
            war_mode: env::var("WAR_MODE")
                .ok()
                .map(|v| {
                    matches!(
                        v.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(false),
        })
    }
}
