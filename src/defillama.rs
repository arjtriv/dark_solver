use alloy::primitives::{Address, Bytes as ABytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionInput, TransactionRequest};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::storage::contracts_db::ContractsDb;
use crate::target_queue::{TargetPriority, TargetQueueSender};

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

// Protocol list — https://api.llama.fi/protocols
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Protocol {
    name: Option<String>,
    /// Comma-separated, chain-prefixed addresses: "base:0xabc...,ethereum:0xdef..."
    address: Option<String>,
    /// Per-chain TVL breakdown: { "Base": 1234.5, ... }
    chain_tvls: Option<serde_json::Value>,
    /// List of chains this protocol is on
    chains: Option<Vec<String>>,
    /// Protocol slug (e.g. "aerodrome-v2")
    slug: Option<String>,
    /// Category (e.g. "Dexes", "Lending", "Yield")
    category: Option<String>,
}

// Yield pools list — https://yields.llama.fi/pools
#[derive(Deserialize, Serialize, Clone)]
struct YieldsPoolsResponse {
    data: Vec<YieldsPool>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct YieldsPool {
    /// The pool contract address (0x...) for EVM chains.
    pool: String,
    chain: Option<String>,
    project: Option<String>,
    symbol: Option<String>,
    tvl_usd: Option<f64>,
}

#[derive(Deserialize, Serialize)]
struct CacheEnvelope<T> {
    fetched_at_ms: u64,
    data: T,
}

// ---------------------------------------------------------------------------
// Address parsing — handles multi-chain "base:0x...,ethereum:0x..." format
// ---------------------------------------------------------------------------

fn parse_address(raw: &str) -> Option<Address> {
    let candidate = raw.trim();
    if candidate.len() == 42 && candidate.starts_with("0x") {
        return Address::from_str(candidate).ok();
    }
    // Handle common chain-prefixed variants like "base:0x...".
    if let Some((_, suffix)) = candidate.rsplit_once(':') {
        let suffix = suffix.trim();
        if suffix.len() == 42 && suffix.starts_with("0x") {
            if let Ok(addr) = Address::from_str(suffix) {
                return Some(addr);
            }
        }
    }
    // Fallback: extract the first 0x + 40 hex chars anywhere in the string.
    let bytes = candidate.as_bytes();
    if bytes.len() >= 42 {
        for i in 0..=bytes.len().saturating_sub(42) {
            if bytes[i] == b'0' && bytes[i + 1] == b'x' {
                let end = i + 42;
                if bytes[i + 2..end].iter().all(|b| b.is_ascii_hexdigit()) {
                    if let Ok(slice) = std::str::from_utf8(&bytes[i..end]) {
                        if let Ok(addr) = Address::from_str(slice) {
                            return Some(addr);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract all addresses for a given chain from the protocol's address field.
/// Format: "base:0xabc...,ethereum:0xdef..." — we want all "base:" prefixed ones.
fn extract_chain_addresses(address_field: &str, chain_name: &str) -> Vec<Address> {
    let chain_lower = chain_name.to_lowercase();
    let mut addrs = Vec::new();

    for segment in address_field.split(',') {
        let segment = segment.trim();
        if let Some((chain, addr_part)) = segment.split_once(':') {
            if chain.trim().to_lowercase() == chain_lower {
                if let Some(a) = parse_address(addr_part) {
                    addrs.push(a);
                }
            }
        } else {
            // Bare address with no chain prefix — include it
            if let Some(a) = parse_address(segment) {
                addrs.push(a);
            }
        }
    }
    addrs
}

/// Get the TVL for a specific chain from chainTvls JSON object.
fn get_chain_tvl(chain_tvls: &serde_json::Value, chain_name: &str) -> f64 {
    // chainTvls can have exact key "Base" or lowercase; try both
    if let Some(v) = chain_tvls.get(chain_name).and_then(|v| v.as_f64()) {
        return v;
    }
    // Fallback: case-insensitive search
    if let Some(obj) = chain_tvls.as_object() {
        for (k, v) in obj {
            if k.eq_ignore_ascii_case(chain_name) {
                if let Some(f) = v.as_f64() {
                    return f;
                }
            }
        }
    }
    0.0
}

// ---------------------------------------------------------------------------
// HTTP fetch with retries
// ---------------------------------------------------------------------------

const PROTOCOLS_API_URL: &str = "https://api.llama.fi/protocols";
const YIELDS_POOLS_API_URL: &str = "https://yields.llama.fi/pools";
const MAX_RETRIES: u32 = 3;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn load_defillama_cache_enabled() -> bool {
    std::env::var("DEFILLAMA_CACHE_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn load_defillama_cache_ttl_secs() -> u64 {
    std::env::var("DEFILLAMA_CACHE_TTL_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(24 * 60 * 60)
}

fn defillama_cache_dir() -> PathBuf {
    std::env::var("DEFILLAMA_CACHE_DIR")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/defillama_cache"))
}

fn cache_path(name: &str) -> PathBuf {
    defillama_cache_dir().join(name)
}

fn read_cache_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<CacheEnvelope<T>> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<CacheEnvelope<T>>(&raw).ok()
}

fn write_cache_json<T: Serialize>(path: &Path, data: &CacheEnvelope<T>) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let _ = fs::create_dir_all(parent);
    let Ok(raw) = serde_json::to_string(data) else {
        return;
    };
    let _ = fs::write(path, raw);
}

async fn fetch_protocols(client: &reqwest::Client) -> Result<Vec<Protocol>> {
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let backoff = Duration::from_millis(1000 * 2u64.pow(attempt - 1));
            tokio::time::sleep(backoff).await;
        }

        match client
            .get(PROTOCOLS_API_URL)
            .timeout(Duration::from_secs(30))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    last_err = Some(anyhow::anyhow!("HTTP {}", status));
                    continue;
                }
                match resp.json::<Vec<Protocol>>().await {
                    Ok(protocols) => return Ok(protocols),
                    Err(e) => {
                        last_err = Some(e.into());
                        continue;
                    }
                }
            }
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("fetch_protocols: no attempts made")))
}

async fn fetch_yields_pools(client: &reqwest::Client) -> Result<Vec<YieldsPool>> {
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            let backoff = Duration::from_millis(1000 * 2u64.pow(attempt - 1));
            tokio::time::sleep(backoff).await;
        }

        match client
            .get(YIELDS_POOLS_API_URL)
            .timeout(Duration::from_secs(30))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    last_err = Some(anyhow::anyhow!("HTTP {}", status));
                    continue;
                }
                match resp.json::<YieldsPoolsResponse>().await {
                    Ok(pools) => return Ok(pools.data),
                    Err(e) => {
                        last_err = Some(e.into());
                        continue;
                    }
                }
            }
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("fetch_yields_pools: no attempts made")))
}

async fn fetch_yields_pools_cached(client: &reqwest::Client) -> Result<Vec<YieldsPool>> {
    let cache_enabled = load_defillama_cache_enabled();
    let cache_ttl_secs = load_defillama_cache_ttl_secs();
    let path = cache_path("yields_pools.json");

    match fetch_yields_pools(client).await {
        Ok(pools) => {
            if cache_enabled {
                let env = CacheEnvelope {
                    fetched_at_ms: now_ms(),
                    data: pools.clone(),
                };
                let _ = tokio::task::spawn_blocking(move || write_cache_json(path.as_path(), &env))
                    .await;
            }
            Ok(pools)
        }
        Err(err) => {
            if cache_enabled {
                if let Some(env) = read_cache_json::<Vec<YieldsPool>>(path.as_path()) {
                    let age_ms = now_ms().saturating_sub(env.fetched_at_ms);
                    let ttl_ms = cache_ttl_secs.saturating_mul(1000);
                    if ttl_ms == 0 || age_ms <= ttl_ms {
                        eprintln!(
                            "[DEFILLAMA] Using cached yields pools (age={}s, items={})",
                            age_ms / 1000,
                            env.data.len()
                        );
                        return Ok(env.data);
                    }
                }
            }
            Err(err)
        }
    }
}

async fn fetch_protocols_cached(client: &reqwest::Client) -> Result<Vec<Protocol>> {
    let cache_enabled = load_defillama_cache_enabled();
    let cache_ttl_secs = load_defillama_cache_ttl_secs();
    let path = cache_path("protocols.json");

    match fetch_protocols(client).await {
        Ok(protocols) => {
            if cache_enabled {
                let env = CacheEnvelope {
                    fetched_at_ms: now_ms(),
                    data: protocols.clone(),
                };
                let _ = tokio::task::spawn_blocking(move || write_cache_json(path.as_path(), &env))
                    .await;
            }
            Ok(protocols)
        }
        Err(err) => {
            if cache_enabled {
                if let Some(env) = read_cache_json::<Vec<Protocol>>(path.as_path()) {
                    let age_ms = now_ms().saturating_sub(env.fetched_at_ms);
                    let ttl_ms = cache_ttl_secs.saturating_mul(1000);
                    if ttl_ms == 0 || age_ms <= ttl_ms {
                        eprintln!(
                            "[DEFILLAMA] Using cached protocols list (age={}s, items={})",
                            age_ms / 1000,
                            env.data.len()
                        );
                        return Ok(env.data);
                    }
                }
            }
            Err(err)
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved target: address + metadata
// ---------------------------------------------------------------------------

struct ResolvedTarget {
    address: Address,
    tvl: f64,
    protocol_name: String,
    category: String,
}

fn load_write_targets_enabled() -> bool {
    std::env::var("DEFILLAMA_WRITE_TARGETS")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn defillama_targets_dir() -> PathBuf {
    std::env::var("DEFILLAMA_TARGETS_DIR")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/targets"))
}

fn write_targets_files(targets: &[ResolvedTarget]) {
    if !load_write_targets_enabled() {
        return;
    }
    let dir = defillama_targets_dir();
    let _ = fs::create_dir_all(&dir);

    // Stable deterministic list for other tools (deep_miner, offline audits, etc.)
    let list_path = dir.join("defillama_targets.txt");
    let mut out = String::new();
    for t in targets {
        out.push_str(&format!("{:#x}\n", t.address));
    }
    let _ = fs::write(list_path, out);

    // Metadata for debugging/triage.
    let jsonl_path = dir.join("defillama_targets.jsonl");
    let mut jsonl = String::new();
    for t in targets {
        let rec = serde_json::json!({
            "address": format!("{:#x}", t.address),
            "tvl_usd": t.tvl,
            "name": t.protocol_name,
            "category": t.category,
        });
        jsonl.push_str(&rec.to_string());
        jsonl.push('\n');
    }
    let _ = fs::write(jsonl_path, jsonl);
}

fn load_defillama_source() -> String {
    std::env::var("DEFILLAMA_SOURCE")
        .unwrap_or_else(|_| "yields".into())
        .trim()
        .to_ascii_lowercase()
}

fn yields_pool_chain_matches(pool: &YieldsPool, chain_name: &str) -> bool {
    pool.chain
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case(chain_name))
}

fn yields_pool_tvl_usd(pool: &YieldsPool) -> f64 {
    pool.tvl_usd.unwrap_or(0.0)
}

fn yields_pool_project(pool: &YieldsPool) -> String {
    pool.project
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}

fn yields_pool_symbol(pool: &YieldsPool) -> String {
    pool.symbol.clone().unwrap_or_else(|| "?".to_string())
}

// ---------------------------------------------------------------------------
// On-chain factory resolution — resolve protocol categories to actual contracts
// ---------------------------------------------------------------------------

struct KnownFactory {
    name: &'static str,
    address: Address,
    /// Categories this factory is relevant for
    categories: &'static [&'static str],
    /// Selector for allPoolsLength() or equivalent
    length_selector: [u8; 4],
    /// Selector for allPools(uint256) or equivalent
    getter_selector: [u8; 4],
    /// Max pools to enumerate
    max_enumerate: usize,
}

fn base_known_factories() -> Vec<KnownFactory> {
    vec![KnownFactory {
        name: "Aerodrome",
        address: Address::from_str("0x420DD381b31aEf6683db6B902084cB0FFECe40Da").unwrap(),
        categories: &["Dexes", "Dexs", "DEX"],
        length_selector: [0xef, 0xb7, 0x60, 0x1d], // allPoolsLength()
        getter_selector: [0x41, 0xd1, 0xde, 0x97], // allPools(uint256)
        max_enumerate: 100,
    }]
}

/// Factories that return address[] from a single call (no indexed getter).
struct KnownArrayFactory {
    name: &'static str,
    address: Address,
    categories: &'static [&'static str],
    /// Selector for function returning address[]
    selector: [u8; 4],
}

fn base_known_array_factories() -> Vec<KnownArrayFactory> {
    vec![KnownArrayFactory {
        name: "Moonwell",
        address: Address::from_str("0xfBb21d0380beE3312B33c4353c8936a0F13EF26C").unwrap(),
        categories: &["Lending"],
        selector: [0xb0, 0x77, 0x2d, 0x0b], // getAllMarkets()
    }]
}

/// Well-known core contracts to inject when we see matching protocol categories.
/// These are the actual routers/vaults/singletons — not governance tokens.
fn base_known_protocol_contracts() -> Vec<(Address, &'static str, &'static [&'static str])> {
    vec![
        (
            Address::from_str("0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43").unwrap(),
            "Aerodrome V2 Router",
            &["Dexes", "Dexs", "DEX"],
        ),
        (
            Address::from_str("0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb").unwrap(),
            "Morpho Blue",
            &["Lending", "CDP"],
        ),
        (
            Address::from_str("0xfBb21d0380beE3312B33c4353c8936a0F13EF26C").unwrap(),
            "Moonwell Comptroller",
            &["Lending"],
        ),
        (
            Address::from_str("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5").unwrap(),
            "Aave V3 Pool",
            &["Lending"],
        ),
    ]
}

/// Resolve actual on-chain contract addresses for known protocol categories.
/// Returns additional addresses discovered from factory enumeration and known contracts.
async fn resolve_protocol_contracts(categories_seen: &HashSet<String>) -> Vec<(Address, String)> {
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://base-rpc.publicnode.com".into());

    let mut resolved = Vec::new();

    // 1. Add known protocol contracts for matching categories
    for (addr, name, cats) in base_known_protocol_contracts() {
        if cats.iter().any(|c| categories_seen.contains(*c)) {
            resolved.push((addr, name.to_string()));
        }
    }

    // 2. Enumerate factory pools for matching categories
    let provider = match rpc_url
        .parse()
        .map(|url| ProviderBuilder::new().on_http(url))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[DEFILLAMA] Failed to create provider for factory resolution: {:?}",
                e
            );
            return resolved;
        }
    };

    // 2a. Indexed factories (length + getter pattern)
    for factory in base_known_factories() {
        let category_match = factory
            .categories
            .iter()
            .any(|c| categories_seen.contains(*c));
        if !category_match {
            continue;
        }

        let length_calldata = ABytes::from(factory.length_selector.to_vec());
        let length_tx = TransactionRequest::default()
            .to(factory.address)
            .input(TransactionInput::new(length_calldata));

        let total = match provider.call(&length_tx).await {
            Ok(result) if result.len() >= 32 => U256::from_be_slice(&result[..32])
                .try_into()
                .unwrap_or(0usize),
            Ok(_) => continue,
            Err(e) => {
                eprintln!(
                    "[DEFILLAMA] {} factory length call failed: {:?}",
                    factory.name, e
                );
                continue;
            }
        };

        let enumerate_count = total.min(factory.max_enumerate);
        eprintln!(
            "[DEFILLAMA] {} factory: {} total pools, enumerating last {}",
            factory.name, total, enumerate_count
        );

        for i in 0..enumerate_count {
            let idx = total.saturating_sub(1).saturating_sub(i);
            let idx_u256 = U256::from(idx);
            let mut calldata = Vec::with_capacity(36);
            calldata.extend_from_slice(&factory.getter_selector);
            calldata.extend_from_slice(&idx_u256.to_be_bytes::<32>());

            let tx = TransactionRequest::default()
                .to(factory.address)
                .input(TransactionInput::new(ABytes::from(calldata)));

            match provider.call(&tx).await {
                Ok(result) if result.len() >= 32 => {
                    let addr = Address::from_slice(&result[12..32]);
                    if !addr.is_zero() {
                        resolved.push((addr, format!("{} Pool #{}", factory.name, idx)));
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "[DEFILLAMA] {} pool enumeration error at index {}: {}",
                        factory.name, idx, e
                    );
                    break;
                }
            }

            if i % 20 == 19 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    // 2b. Array-return factories (e.g. Moonwell getAllMarkets)
    for factory in base_known_array_factories() {
        let category_match = factory
            .categories
            .iter()
            .any(|c| categories_seen.contains(*c));
        if !category_match {
            continue;
        }

        let calldata = ABytes::from(factory.selector.to_vec());
        let tx = TransactionRequest::default()
            .to(factory.address)
            .input(TransactionInput::new(calldata));

        match provider.call(&tx).await {
            Ok(result) if result.len() >= 64 => {
                let len: usize = U256::from_be_slice(&result[32..64]).try_into().unwrap_or(0);
                let mut count = 0u32;
                for i in 0..len {
                    let start = 64 + i * 32;
                    if start + 32 > result.len() {
                        break;
                    }
                    let addr = Address::from_slice(&result[start + 12..start + 32]);
                    if !addr.is_zero() {
                        resolved.push((addr, format!("{} Market #{}", factory.name, i)));
                        count += 1;
                    }
                }
                eprintln!(
                    "[DEFILLAMA] {} array factory: {} markets resolved",
                    factory.name, count
                );
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "[DEFILLAMA] {} array factory call failed: {:?}",
                    factory.name, e
                );
            }
        }
    }

    resolved
}

// ---------------------------------------------------------------------------
// Single cycle: fetch, filter, enqueue
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_one_cycle(
    client: &reqwest::Client,
    target_sender: &TargetQueueSender,
    contracts_db: &Option<ContractsDb>,
    chain_name: &str,
    min_tvl: f64,
    max_tvl: f64,
    max_targets: usize,
    exclude_projects: &[String],
    enqueue_delay: Duration,
) -> Result<usize> {
    let mut targets: Vec<ResolvedTarget> = Vec::new();
    let mut seen_addrs: HashSet<Address> = HashSet::new();
    let mut skipped_excluded = 0u32;
    let mut skipped_tvl = 0u32;
    let mut skipped_chain = 0u32;
    let mut skipped_no_addr = 0u32;
    let mut source_yields_added = 0u32;
    let mut source_protocols_added = 0u32;
    let mut categories_seen: HashSet<String> = HashSet::new();
    let mut projects_seen: HashSet<String> = HashSet::new();

    let source = load_defillama_source();
    let use_yields = matches!(source.as_str(), "yields" | "both" | "auto");
    let use_protocols = matches!(source.as_str(), "protocols" | "both");

    // 1) Primary: yields pools feed (real pool/market contract addresses).
    if use_yields {
        let pools = fetch_yields_pools_cached(client).await?;
        eprintln!("[DEFILLAMA] Fetched {} yield pools from API.", pools.len());

        for pool in &pools {
            if !yields_pool_chain_matches(pool, chain_name) {
                skipped_chain += 1;
                continue;
            }

            let project = yields_pool_project(pool);
            if exclude_projects
                .iter()
                .any(|ex| ex.eq_ignore_ascii_case(&project))
            {
                skipped_excluded += 1;
                continue;
            }

            let tvl = yields_pool_tvl_usd(pool);
            if tvl < min_tvl || (max_tvl > 0.0 && tvl > max_tvl) {
                skipped_tvl += 1;
                continue;
            }
            projects_seen.insert(project.to_ascii_lowercase());

            let Some(addr) = parse_address(pool.pool.as_str()) else {
                skipped_no_addr += 1;
                continue;
            };

            if seen_addrs.insert(addr) {
                let symbol = yields_pool_symbol(pool);
                targets.push(ResolvedTarget {
                    address: addr,
                    tvl,
                    protocol_name: format!("{project} [{symbol}] (yields)"),
                    category: "Yields".to_string(),
                });
                source_yields_added += 1;
            }
        }
    }

    // 2) Optional: protocol list feed (kept for category mapping and legacy "address" field).
    // Note: protocol "address" fields often point at tokens/governance addresses. We treat this
    // source as optional and default to the yields pool feed for real contract discovery.
    if use_protocols {
        let protocols = fetch_protocols_cached(client).await?;
        eprintln!(
            "[DEFILLAMA] Fetched {} protocols from API.",
            protocols.len()
        );

        for proto in &protocols {
            let on_chain = proto
                .chains
                .as_ref()
                .map(|chains| chains.iter().any(|c| c.eq_ignore_ascii_case(chain_name)))
                .unwrap_or(false);
            if !on_chain {
                continue;
            }

            let slug = proto.slug.as_deref().unwrap_or("");
            let name = proto.name.as_deref().unwrap_or("");
            if exclude_projects
                .iter()
                .any(|ex| ex.eq_ignore_ascii_case(slug) || ex.eq_ignore_ascii_case(name))
            {
                continue;
            }

            if let Some(cat) = proto.category.as_deref() {
                if !cat.is_empty() {
                    categories_seen.insert(cat.to_string());
                }
            }

            // Legacy: include addresses if present, but this is not the default discovery path.
            let tvl = proto
                .chain_tvls
                .as_ref()
                .map(|ct| get_chain_tvl(ct, chain_name))
                .unwrap_or(0.0);
            if tvl < min_tvl || (max_tvl > 0.0 && tvl > max_tvl) {
                continue;
            }
            let addrs = match proto.address.as_deref() {
                Some(a) if !a.is_empty() => extract_chain_addresses(a, chain_name),
                _ => continue,
            };
            let cat = proto.category.as_deref().unwrap_or("Unknown").to_string();
            let proto_name = format!("{} ({})", name, slug);
            for addr in addrs {
                if seen_addrs.insert(addr) {
                    targets.push(ResolvedTarget {
                        address: addr,
                        tvl,
                        protocol_name: proto_name.clone(),
                        category: cat.clone(),
                    });
                    source_protocols_added += 1;
                }
            }
        }
    }

    // 3) Resolve actual DeFi contracts from known factories for seen categories.
    // If we didn't ingest categories via the protocol list, derive a minimal set from
    // yields projects to keep factory enrichment available without requiring protocol addresses.
    if categories_seen.is_empty() {
        for project in &projects_seen {
            if project.contains("aave")
                || project.contains("compound")
                || project.contains("moonwell")
                || project.contains("morpho")
            {
                categories_seen.insert("Lending".to_string());
            }
            if project.contains("aerodrome")
                || project.contains("uniswap")
                || project.contains("curve")
                || project.contains("balancer")
            {
                categories_seen.insert("Dexes".to_string());
            }
        }
        for t in &targets {
            let name = t.protocol_name.to_ascii_lowercase();
            if name.contains("aave")
                || name.contains("compound")
                || name.contains("moonwell")
                || name.contains("morpho")
            {
                categories_seen.insert("Lending".to_string());
            }
            if name.contains("aerodrome") || name.contains("uniswap") || name.contains("curve") {
                categories_seen.insert("Dexes".to_string());
            }
        }
    }
    let factory_contracts = resolve_protocol_contracts(&categories_seen).await;
    let mut factory_added = 0u32;
    for (addr, name) in factory_contracts {
        if seen_addrs.insert(addr) {
            targets.push(ResolvedTarget {
                address: addr,
                tvl: min_tvl, // Give factory pools base TVL so they're included
                protocol_name: name,
                category: "Factory".to_string(),
            });
            factory_added += 1;
        }
    }
    if factory_added > 0 {
        eprintln!(
            "[DEFILLAMA] Resolved {} additional contracts from on-chain factories",
            factory_added
        );
    }

    // 3. Sort by TVL descending
    targets.sort_by(|a, b| {
        b.tvl
            .partial_cmp(&a.tvl)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // 4. Truncate
    targets.truncate(max_targets);
    write_targets_files(&targets);

    eprintln!(
        "[DEFILLAMA] {} targets resolved (chain={}, tvl=${:.0}-${}, source={}, yields_added={}, protocols_added={}, excluded={}, no_addr={}, tvl_skip={}, chain_skip={})",
        targets.len(),
        chain_name,
        min_tvl,
        if max_tvl <= 0.0 {
            "inf".to_string()
        } else {
            format!("{:.0}", max_tvl)
        },
        source,
        source_yields_added,
        source_protocols_added,
        skipped_excluded,
        skipped_no_addr,
        skipped_tvl,
        skipped_chain,
    );

    // 5. Enqueue
    let mut enqueued = 0usize;
    for target in &targets {
        // Reset Done status so the main loop will re-analyze
        if let Some(db) = contracts_db {
            let _ = db.mark_queued(target.address);
        }

        let priority = if target.category == "Factory" {
            TargetPriority::Hot
        } else {
            TargetPriority::Normal
        };
        if target_sender.enqueue(target.address, priority).await {
            enqueued += 1;
            if enqueued <= 20 {
                eprintln!(
                    "[DEFILLAMA]   #{}: {:?} — {} [{}] (TVL ${:.0})",
                    enqueued, target.address, target.protocol_name, target.category, target.tvl,
                );
            }
        }

        tokio::time::sleep(enqueue_delay).await;
    }

    Ok(enqueued)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn start_defillama_feeder(
    target_sender: TargetQueueSender,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    contracts_db: Option<ContractsDb>,
) -> Result<()> {
    // Self-disable check
    let enabled = std::env::var("DEFILLAMA_ENABLED")
        .unwrap_or_else(|_| "false".into())
        .eq_ignore_ascii_case("true");

    if !enabled {
        eprintln!("[DEFILLAMA] Disabled (DEFILLAMA_ENABLED != true). Exiting feeder.");
        return Ok(());
    }

    // Read configuration from env
    let chain_name = std::env::var("DEFILLAMA_CHAIN_NAME").unwrap_or_else(|_| "Base".into());
    let min_tvl: f64 = std::env::var("DEFILLAMA_MIN_TVL_USD")
        .unwrap_or_else(|_| "50000".into())
        .parse()
        .unwrap_or(50_000.0);
    let max_tvl: f64 = std::env::var("DEFILLAMA_MAX_TVL_USD")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .unwrap_or(0.0); // 0 = no ceiling
    let max_targets: usize = std::env::var("DEFILLAMA_MAX_TARGETS")
        .unwrap_or_else(|_| "500".into())
        .parse()
        .unwrap_or(500);
    let rescan_secs: u64 = std::env::var("DEFILLAMA_RESCAN_INTERVAL_SECS")
        .unwrap_or_else(|_| "3600".into())
        .parse()
        .unwrap_or(3600);
    let enqueue_delay_ms: u64 = std::env::var("DEFILLAMA_ENQUEUE_DELAY_MS")
        .unwrap_or_else(|_| "50".into())
        .parse()
        .unwrap_or(50);
    let exclude_projects: Vec<String> = std::env::var("DEFILLAMA_EXCLUDE_PROJECTS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let enqueue_delay = Duration::from_millis(enqueue_delay_ms);
    let rescan_interval = Duration::from_secs(rescan_secs);
    let retry_secs: u64 = std::env::var("DEFILLAMA_RETRY_SECS")
        .unwrap_or_else(|_| "60".into())
        .parse()
        .unwrap_or(60);
    let retry_interval = Duration::from_secs(retry_secs.max(1).min(rescan_secs.max(1)));

    eprintln!(
        "[DEFILLAMA] Starting feeder: chain={}, tvl=${:.0}-${}, max_targets={}, rescan={}s, excluded={:?}, source={}",
        chain_name,
        min_tvl,
        if max_tvl <= 0.0 { "inf".to_string() } else { format!("{:.0}", max_tvl) },
        max_targets,
        rescan_secs,
        exclude_projects,
        load_defillama_source(),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    // Auto-expansion: if we exhaust the TVL band, widen the ceiling each cycle
    let mut effective_max_tvl = max_tvl;

    loop {
        let cycle_res = run_one_cycle(
            &client,
            &target_sender,
            &contracts_db,
            &chain_name,
            min_tvl,
            effective_max_tvl,
            max_targets,
            &exclude_projects,
            enqueue_delay,
        )
        .await;

        let sleep_for = match cycle_res {
            Ok(count) => {
                eprintln!("[DEFILLAMA] Cycle complete: enqueued {} targets.", count);

                // Auto-expand: if ceiling is set and we got fewer targets than
                // max_targets, the band is exhausted — double the ceiling to
                // include higher-TVL contracts next cycle.
                if effective_max_tvl > 0.0 && count < max_targets {
                    let old = effective_max_tvl;
                    effective_max_tvl *= 2.0;
                    eprintln!(
                        "[DEFILLAMA] Band exhausted ({} < {} targets). Expanding ceiling ${:.0} -> ${:.0}",
                        count, max_targets, old, effective_max_tvl
                    );
                }
                rescan_interval
            }
            Err(e) => {
                eprintln!(
                    "[DEFILLAMA] Cycle failed: {:?}. Retrying in {}s (rescan={}s).",
                    e,
                    retry_interval.as_secs(),
                    rescan_secs
                );
                retry_interval
            }
        };

        // Sleep until next cycle, but respect shutdown
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            _ = shutdown_rx.recv() => {
                eprintln!("[DEFILLAMA] Shutdown signal received. Exiting feeder.");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_bare() {
        let addr = parse_address("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5");
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_address_invalid() {
        assert!(parse_address("not-an-address").is_none());
        assert!(parse_address("0xshort").is_none());
        assert!(parse_address("").is_none());
    }

    #[test]
    fn test_extract_chain_addresses_multi() {
        let addrs = extract_chain_addresses(
            "base:0xA238Dd80C259a72e81d7e4664a9801593F98d1c5,ethereum:0xBA12222222228d8Ba445958a75a0704d566BF2C8",
            "Base",
        );
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0],
            Address::from_str("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5").unwrap()
        );
    }

    #[test]
    fn test_extract_chain_addresses_bare() {
        let addrs = extract_chain_addresses("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", "Base");
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn test_extract_chain_addresses_none_for_chain() {
        let addrs = extract_chain_addresses(
            "ethereum:0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
            "Base",
        );
        assert_eq!(addrs.len(), 0);
    }

    #[test]
    fn test_get_chain_tvl() {
        let json: serde_json::Value = serde_json::json!({
            "Base": 123456.78,
            "Ethereum": 999999.0,
        });
        assert!((get_chain_tvl(&json, "Base") - 123456.78).abs() < 0.01);
        assert!((get_chain_tvl(&json, "Arbitrum")).abs() < 0.01);
    }

    #[test]
    fn test_parse_yields_pool_response() {
        let raw = r#"{ "status": "success", "data": [
            { "pool": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", "chain": "Base", "project": "aave-v3", "symbol": "WETH", "tvlUsd": 100000.0 },
            { "pool": "not-an-address", "chain": "Base", "project": "x", "tvlUsd": 100.0 }
        ]}"#;
        let parsed: YieldsPoolsResponse = serde_json::from_str(raw).expect("parse");
        assert_eq!(parsed.data.len(), 2);
        assert!(parse_address(&parsed.data[0].pool).is_some());
        assert!(parse_address(&parsed.data[1].pool).is_none());
    }
}
