use alloy::providers::Provider;
use dashmap::DashMap;
use revm::{
    primitives::{AccountInfo, Address as rAddress, Bytecode, Bytes as rBytes, U256 as rU256},
    Database, DatabaseRef,
};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

pub const EIP1967_BEACON_SLOT: [u8; 32] = [
    0xa3, 0xf0, 0xad, 0x74, 0xe5, 0x42, 0x3a, 0xeb, 0xfd, 0x80, 0xd3, 0xef, 0x43, 0x46, 0x57, 0x83,
    0x35, 0xa9, 0xa7, 0x2a, 0xea, 0xee, 0x59, 0xff, 0x6c, 0xb3, 0x58, 0x2b, 0x35, 0x13, 0x3d, 0x50,
];

const DEBUG_STORAGE_MODE_UNKNOWN: u8 = 0;
const DEBUG_STORAGE_MODE_SUPPORTED: u8 = 1;
const DEBUG_STORAGE_MODE_UNSUPPORTED: u8 = 2;
const MAX_BLOCK_HASH_CACHE_ENTRIES: usize = 2048;
const MAX_STORAGE_CACHE_ENTRIES: usize = 200_000;
const MAX_ACCOUNT_INFO_CACHE_ENTRIES: usize = 100_000;
const DEFAULT_BRIDGE_TIMEOUT_MS: u64 = 10_000;
const BRIDGE_WORKER_QUEUE_CAPACITY: usize = 256;

type BridgeJob = Box<dyn FnOnce() + Send + 'static>;

pub fn decode_low160_address_from_word(word: rU256) -> Option<rAddress> {
    let bytes = word.to_be_bytes::<32>();
    let addr = rAddress::from_slice(&bytes[12..]);
    if addr == rAddress::ZERO {
        None
    } else {
        Some(addr)
    }
}

/// Decode ABI-encoded `address[]` return data.
///
/// Layout:
/// - 0x00: offset to data (0x20)
/// - 0x20: length (N)
/// - 0x40..: N x 32-byte words, each containing address in low 20 bytes
pub fn decode_abi_address_array(data: &[u8], max: usize) -> Vec<rAddress> {
    let mut out = Vec::new();
    if max == 0 {
        return out;
    }
    if data.len() < 64 {
        return out;
    }
    let mut offset_word = [0u8; 32];
    offset_word.copy_from_slice(&data[0..32]);
    let offset = rU256::from_be_bytes(offset_word);
    let offset_u: usize = match u64::try_from(offset) {
        Ok(v) => v as usize,
        Err(_) => return out,
    };
    if offset_u + 32 > data.len() {
        return out;
    }
    let mut len_buf = [0u8; 32];
    len_buf.copy_from_slice(&data[offset_u..offset_u + 32]);
    let len_word = rU256::from_be_bytes(len_buf);
    let len_u: usize = match u64::try_from(len_word) {
        Ok(v) => v as usize,
        Err(_) => return out,
    };
    let count = len_u.min(max);
    let mut cursor = offset_u + 32;
    for _ in 0..count {
        if cursor + 32 > data.len() {
            break;
        }
        let mut raw_word = [0u8; 32];
        raw_word.copy_from_slice(&data[cursor..cursor + 32]);
        let word = rU256::from_be_bytes(raw_word);
        if let Some(addr) = decode_low160_address_from_word(word) {
            out.push(addr);
        }
        cursor += 32;
    }
    out
}

#[derive(Clone)]
pub struct ForkDB {
    pool: crate::utils::rpc::HydrationProviderPool,
    handle: tokio::runtime::Handle,
    runtime_guard: Option<Arc<tokio::runtime::Runtime>>,
    block_number: Option<u64>,
    rpc_urls: Arc<Vec<String>>,
    block_hash_cache: Arc<DashMap<u64, revm::primitives::B256>>,
    code_by_hash_cache: Arc<DashMap<revm::primitives::B256, Bytecode>>,
    storage_cache: Arc<
        DashMap<
            (alloy::primitives::Address, alloy::primitives::U256, u64),
            alloy::primitives::U256,
        >,
    >,
    account_info_cache: Arc<DashMap<(alloy::primitives::Address, u64), Option<AccountInfo>>>,
    debug_storage_range_mode: Arc<AtomicU8>,
}

impl ForkDB {
    fn bridge_worker_sender() -> &'static std::sync::mpsc::SyncSender<BridgeJob> {
        static TX: OnceLock<std::sync::mpsc::SyncSender<BridgeJob>> = OnceLock::new();
        TX.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<BridgeJob>(BRIDGE_WORKER_QUEUE_CAPACITY);
            let _ = std::thread::Builder::new()
                .name("forkdb-bridge-worker".to_string())
                .spawn(move || {
                    while let Ok(job) = rx.recv() {
                        job();
                    }
                });
            tx
        })
    }

    fn shared_http_client() -> &'static reqwest::Client {
        static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
        HTTP_CLIENT.get_or_init(|| {
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(2_000))
                .build()
            {
                Ok(client) => client,
                Err(err) => {
                    eprintln!(
                        "[FORKDB] Warning: failed to construct timeout HTTP client: {err}. Falling back to default client."
                    );
                    reqwest::Client::new()
                }
            }
        })
    }

    pub fn new(url: &str) -> anyhow::Result<Self> {
        let env_block = std::env::var("FORKDB_PIN_BLOCK_NUMBER")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok());
        Self::new_with_block(url, env_block)
    }

    pub fn with_block_number(url: &str, block_number: u64) -> anyhow::Result<Self> {
        Self::new_with_block(url, Some(block_number))
    }

    fn new_with_block(url: &str, block_number: Option<u64>) -> anyhow::Result<Self> {
        let primary_url = url.trim();
        let (pool, rpc_urls) = crate::utils::rpc::build_hydration_provider_pool(primary_url)?;
        let block_hash_cache = Arc::new(DashMap::new());
        let code_by_hash_cache = Arc::new(DashMap::new());
        let storage_cache = Arc::new(DashMap::new());
        let account_info_cache = Arc::new(DashMap::new());
        let debug_storage_range_mode = Arc::new(AtomicU8::new(DEBUG_STORAGE_MODE_UNKNOWN));

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return Ok(Self {
                pool,
                handle,
                runtime_guard: None,
                block_number,
                rpc_urls: Arc::new(rpc_urls),
                block_hash_cache,
                code_by_hash_cache,
                storage_cache,
                account_info_cache,
                debug_storage_range_mode,
            });
        }

        // Some call sites are fully synchronous (tests/tools) and have no ambient runtime.
        // Bootstrap a private multithread runtime for those cases only.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                anyhow::anyhow!("failed to bootstrap tokio runtime for ForkDB: {err}")
            })?;
        let runtime = Arc::new(runtime);
        let handle = runtime.handle().clone();
        Ok(Self {
            pool,
            handle,
            runtime_guard: Some(runtime),
            block_number,
            rpc_urls: Arc::new(rpc_urls),
            block_hash_cache,
            code_by_hash_cache,
            storage_cache,
            account_info_cache,
            debug_storage_range_mode,
        })
    }

    fn compact_error(err: impl std::fmt::Display) -> String {
        crate::utils::error::compact_error_message(&err.to_string(), 220)
    }

    fn debug_storage_unavailable(err: &str) -> bool {
        let err_lc = err.to_ascii_lowercase();
        err_lc.contains("method not found") || err_lc.contains("-32601")
    }

    fn getproof_unavailable(err: &str) -> bool {
        let err_lc = err.to_ascii_lowercase();
        err_lc.contains("method not found")
            || err_lc.contains("unknown method")
            || err_lc.contains("the method eth_getproof does not exist")
            || err_lc.contains("json-rpc error code -32601")
            || (err_lc.contains("eth_getproof") && err_lc.contains("-32601"))
    }

    fn getproof_support_map() -> &'static DashMap<String, bool> {
        static MAP: OnceLock<DashMap<String, bool>> = OnceLock::new();
        MAP.get_or_init(DashMap::new)
    }

    fn bridge_timeout_ms() -> u64 {
        std::env::var("FORKDB_BRIDGE_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|v| *v >= 200)
            .unwrap_or(DEFAULT_BRIDGE_TIMEOUT_MS)
    }

    fn trim_block_hash_cache(cache: &DashMap<u64, revm::primitives::B256>) {
        let len = cache.len();
        if len <= MAX_BLOCK_HASH_CACHE_ENTRIES {
            return;
        }
        let excess = len.saturating_sub(MAX_BLOCK_HASH_CACHE_ENTRIES);
        let keys: Vec<u64> = cache
            .iter()
            .take(excess)
            .map(|entry| *entry.key())
            .collect();
        for key in keys {
            cache.remove(&key);
        }
    }

    fn trim_storage_cache(
        cache: &DashMap<
            (alloy::primitives::Address, alloy::primitives::U256, u64),
            alloy::primitives::U256,
        >,
    ) {
        let len = cache.len();
        if len <= MAX_STORAGE_CACHE_ENTRIES {
            return;
        }
        let excess = len.saturating_sub(MAX_STORAGE_CACHE_ENTRIES);
        let keys: Vec<(alloy::primitives::Address, alloy::primitives::U256, u64)> = cache
            .iter()
            .take(excess)
            .map(|entry| *entry.key())
            .collect();
        for key in keys {
            cache.remove(&key);
        }
    }

    fn trim_account_info_cache(
        cache: &DashMap<(alloy::primitives::Address, u64), Option<AccountInfo>>,
    ) {
        let len = cache.len();
        if len <= MAX_ACCOUNT_INFO_CACHE_ENTRIES {
            return;
        }
        let excess = len.saturating_sub(MAX_ACCOUNT_INFO_CACHE_ENTRIES);
        let keys: Vec<(alloy::primitives::Address, u64)> = cache
            .iter()
            .take(excess)
            .map(|entry| *entry.key())
            .collect();
        for key in keys {
            cache.remove(&key);
        }
    }

    async fn fetch_block_hash_at(
        pool: crate::utils::rpc::HydrationProviderPool,
        number: u64,
    ) -> anyhow::Result<revm::primitives::B256> {
        crate::utils::rpc::run_with_hydration_pool_retry(
            &pool,
            3,
            "eth_getBlockByNumber(hydration pool)",
            move |provider| async move {
                let raw: serde_json::Value = provider
                    .raw_request(
                        std::borrow::Cow::Borrowed("eth_getBlockByNumber"),
                        serde_json::json!([format!("0x{number:x}"), false]),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let hash = raw
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("eth_getBlockByNumber missing hash field"))?;
                let bytes =
                    hex::decode(hash.trim_start_matches("0x")).map_err(anyhow::Error::from)?;
                if bytes.len() != 32 {
                    anyhow::bail!("eth_getBlockByNumber hash wrong length: {}", bytes.len());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(revm::primitives::B256::from(arr))
            },
        )
        .await
    }

    fn u256_from_push_bytes(bytes: &[u8]) -> alloy::primitives::U256 {
        let mut word = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        word[start..].copy_from_slice(bytes);
        alloy::primitives::U256::from_be_bytes(word)
    }

    fn discover_storage_slots_from_bytecode(
        bytecode: &[u8],
        max_slots: usize,
    ) -> Vec<alloy::primitives::U256> {
        let mut discovered = Vec::new();
        let mut seen = HashSet::new();
        let mut stack: Vec<Option<alloy::primitives::U256>> = Vec::new();
        const STACK_WINDOW: usize = 64;
        let mut pc = 0usize;

        while pc < bytecode.len() && discovered.len() < max_slots {
            let op = bytecode[pc];
            if (0x60..=0x7f).contains(&op) {
                let push_len = (op - 0x5f) as usize;
                if pc + 1 + push_len > bytecode.len() {
                    break;
                }
                let pushed = Self::u256_from_push_bytes(&bytecode[pc + 1..pc + 1 + push_len]);
                if stack.len() >= STACK_WINDOW {
                    stack.remove(0);
                }
                stack.push(Some(pushed));
                pc += 1 + push_len;
                continue;
            }

            if (0x80..=0x8f).contains(&op) {
                let depth = (op - 0x7f) as usize;
                let value = if depth <= stack.len() {
                    stack[stack.len().saturating_sub(depth)]
                } else {
                    None
                };
                if stack.len() >= STACK_WINDOW {
                    stack.remove(0);
                }
                stack.push(value);
                pc += 1;
                continue;
            }

            if (0x90..=0x9f).contains(&op) {
                let depth = (op - 0x8f) as usize;
                if depth < stack.len() {
                    let top = stack.len().saturating_sub(1);
                    let other = top.saturating_sub(depth);
                    stack.swap(top, other);
                }
                pc += 1;
                continue;
            }

            if op == 0x54 {
                let slot = stack.pop().unwrap_or(None);
                if let Some(slot) = slot {
                    if seen.insert(slot) {
                        discovered.push(slot);
                    }
                }
                if stack.len() >= STACK_WINDOW {
                    stack.remove(0);
                }
                stack.push(None);
                pc += 1;
                continue;
            }
            if op == 0x55 {
                let slot = stack.pop().unwrap_or(None);
                let _ = stack.pop().unwrap_or(None);
                if let Some(slot) = slot {
                    if seen.insert(slot) {
                        discovered.push(slot);
                    }
                }
                pc += 1;
                continue;
            }
            if op == 0x20 {
                let offset = stack.pop().unwrap_or(None);
                let len = stack.pop().unwrap_or(None);
                if let (Some(seed), Some(span)) = (offset, len) {
                    let word32 = alloy::primitives::U256::from(32u64);
                    let word64 = alloy::primitives::U256::from(64u64);
                    if (span == word32 || span == word64) && seen.insert(seed) {
                        discovered.push(seed);
                    }
                    if (seed == word32 || seed == word64) && seen.insert(span) {
                        discovered.push(span);
                    }
                }
                if stack.len() >= STACK_WINDOW {
                    stack.remove(0);
                }
                stack.push(None);
                pc += 1;
                continue;
            }

            if op == 0x50 {
                let _ = stack.pop().unwrap_or(None);
                pc += 1;
                continue;
            }

            if matches!(
                op,
                0x01 | 0x02
                    | 0x03
                    | 0x04
                    | 0x05
                    | 0x06
                    | 0x07
                    | 0x10
                    | 0x11
                    | 0x12
                    | 0x13
                    | 0x14
                    | 0x15
                    | 0x16
                    | 0x17
                    | 0x18
                    | 0x19
                    | 0x1a
                    | 0x1b
                    | 0x1c
                    | 0x1d
            ) {
                let rhs = stack.pop().unwrap_or(None);
                let lhs = stack.pop().unwrap_or(None);
                let next = match (lhs, rhs) {
                    (Some(a), Some(b)) if op == 0x01 => Some(a.saturating_add(b)),
                    (Some(a), Some(b)) if op == 0x03 => Some(a.saturating_sub(b)),
                    (Some(a), Some(b)) if op == 0x16 => Some(a & b),
                    (Some(a), Some(b)) if op == 0x17 => Some(a | b),
                    (Some(a), Some(b)) if op == 0x18 => Some(a ^ b),
                    _ => None,
                };
                if stack.len() >= STACK_WINDOW {
                    stack.remove(0);
                }
                stack.push(next);
                pc += 1;
                continue;
            }

            // Reset stale PUSH hints at hard control-flow boundaries.
            if matches!(op, 0x00 | 0x56 | 0x57 | 0xf3 | 0xfd | 0xfe | 0xff) {
                stack.clear();
            }

            pc += 1;
        }

        discovered
    }

    fn fallback_storage_slots(
        max_slots: usize,
        discovered_slots: &[alloy::primitives::U256],
    ) -> Vec<alloy::primitives::U256> {
        let mut slots = Vec::new();
        let mut seen = HashSet::new();
        let sequential = max_slots.min(101);
        for i in 0..sequential {
            let slot = alloy::primitives::U256::from(i as u64);
            seen.insert(slot);
            slots.push(slot);
        }

        // Common proxy/introspection slots worth probing even when debug API is unavailable.
        let proxy_slots_hex = [
            // EIP-1967 implementation/admin/beacon slots.
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
            "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
        ];
        for hex_slot in proxy_slots_hex {
            if let Ok(parsed) =
                alloy::primitives::U256::from_str_radix(hex_slot.trim_start_matches("0x"), 16)
            {
                if seen.insert(parsed) {
                    slots.push(parsed);
                }
            }
        }

        for slot in discovered_slots {
            if slots.len() >= max_slots {
                break;
            }
            if seen.insert(*slot) {
                slots.push(*slot);
            }
        }

        slots.truncate(max_slots);
        slots
    }

    pub fn eth_call(&self, to: rAddress, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let addr = alloy::primitives::Address::from_slice(to.as_slice());
        let payload = format!("0x{}", hex::encode(data));
        let pool = self.pool.clone();
        let pinned_block = self.block_number;

        self.block_on_bridge(async move {
            let block_tag = pinned_block
                .map(|b| format!("0x{b:x}"))
                .unwrap_or_else(|| "latest".to_string());
            crate::utils::rpc::run_with_hydration_pool_retry(
                &pool,
                3,
                "eth_call(hydration pool)",
                move |provider| {
                    let call = serde_json::json!({
                        "to": addr,
                        "data": payload,
                    });
                    let block_tag = block_tag.clone();
                    async move {
                        let raw: String = provider
                            .raw_request(
                                std::borrow::Cow::Borrowed("eth_call"),
                                serde_json::json!([call, block_tag]),
                            )
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        let trimmed = raw.trim_start_matches("0x");
                        let bytes = hex::decode(trimmed).map_err(anyhow::Error::from)?;
                        Ok(bytes)
                    }
                },
            )
            .await
        })
    }

    async fn discover_storage_slots_async(
        pool: crate::utils::rpc::HydrationProviderPool,
        address: alloy::primitives::Address,
        max_slots: usize,
        block_number: Option<u64>,
    ) -> Vec<alloy::primitives::U256> {
        let code_res: Option<alloy::primitives::Bytes> = if let Some(block) = block_number {
            crate::utils::rpc::run_with_hydration_pool_retry(
                &pool,
                3,
                "eth_getCode(hydration pool)",
                move |provider| async move {
                    let raw: String = provider
                        .raw_request(
                            std::borrow::Cow::Borrowed("eth_getCode"),
                            serde_json::json!([address, format!("0x{block:x}")]),
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let trimmed = raw.trim_start_matches("0x");
                    let bytes = hex::decode(trimmed).map_err(anyhow::Error::from)?;
                    Ok(alloy::primitives::Bytes::from(bytes))
                },
            )
            .await
            .ok()
        } else {
            crate::utils::rpc::run_with_hydration_pool_retry(
                &pool,
                3,
                "get_code_at(hydration pool)",
                move |provider| async move {
                    let code = provider
                        .get_code_at(address)
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    Ok(code)
                },
            )
            .await
            .ok()
        };

        let Some(code_bytes) = code_res else {
            return Vec::new();
        };

        Self::discover_storage_slots_from_bytecode(code_bytes.as_ref(), max_slots)
    }

    async fn scan_storage_fallback_async(
        pool: crate::utils::rpc::HydrationProviderPool,
        rpc_urls: Arc<Vec<String>>,
        address: alloy::primitives::Address,
        max_slots: usize,
        block_number: Option<u64>,
    ) -> anyhow::Result<Vec<(alloy::primitives::U256, alloy::primitives::U256)>> {
        let mut out = Vec::new();
        let discovered_slots =
            Self::discover_storage_slots_async(pool.clone(), address, max_slots, block_number)
                .await;
        let slots = Self::fallback_storage_slots(max_slots, &discovered_slots);

        let block_tag = match block_number {
            Some(block) => format!("0x{block:x}"),
            None => "latest".to_string(),
        };

        // OPT: Probe many slots per RPC call during sparse scanning.
        // Prefer `eth_getProof(address, storageKeys[], blockTag)` (multi-key) when supported,
        // falling back to JSON-RPC batch `eth_getStorageAt` when not.
        let mut slot_values = HashMap::new();
        let mut direct_probe_attempts = 0usize;
        let mut direct_probe_failures = 0usize;
        if !rpc_urls.is_empty() && !slots.is_empty() {
            let client = Self::shared_http_client();

            if Self::storage_scan_use_getproof() {
                const GETPROOF_BATCH_SIZE: usize = 128; // "100+ slots per RPC call" budget.
                for (batch_idx, chunk) in slots.chunks(GETPROOF_BATCH_SIZE).enumerate() {
                    let mut ok = false;
                    let mut attempts = 0usize;
                    while attempts < rpc_urls.len() {
                        let url = &rpc_urls[(batch_idx + attempts) % rpc_urls.len()];
                        if Self::getproof_support_map()
                            .get(url)
                            .map(|v| !*v.value())
                            .unwrap_or(false)
                        {
                            attempts += 1;
                            continue;
                        }

                        match Self::get_storage_at_via_getproof(
                            client, url, address, chunk, &block_tag,
                        )
                        .await
                        {
                            Ok(map) => {
                                slot_values.extend(map);
                                ok = true;
                                break;
                            }
                            Err(err) if Self::getproof_unavailable(&err.to_string()) => {
                                Self::getproof_support_map().insert(url.clone(), false);
                                attempts += 1;
                                continue;
                            }
                            Err(_) => {
                                break; // Fail closed to batch `eth_getStorageAt` below.
                            }
                        }
                    }

                    if !ok {
                        break; // Fall back to batch mode.
                    }
                }
            }

            let missing = slots
                .iter()
                .copied()
                .filter(|slot| !slot_values.contains_key(slot))
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                if let Ok(map) =
                    Self::batch_get_storage_at_round_robin(&rpc_urls, address, &missing, &block_tag)
                        .await
                {
                    slot_values.extend(map);
                }
            }
        }

        for slot in slots {
            if let Some(value) = slot_values.get(&slot).copied() {
                if !value.is_zero() {
                    out.push((slot, value));
                }
                continue;
            }
            direct_probe_attempts = direct_probe_attempts.saturating_add(1);

            let value_res = if let Some(block) = block_number {
                crate::utils::rpc::run_with_hydration_pool_retry(
                    &pool,
                    3,
                    "eth_getStorageAt(hydration pool)",
                    move |provider| async move {
                        let raw: String = provider
                            .raw_request(
                                std::borrow::Cow::Borrowed("eth_getStorageAt"),
                                serde_json::json!([address, slot, format!("0x{block:x}")]),
                            )
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        let parsed = alloy::primitives::U256::from_str_radix(
                            raw.trim_start_matches("0x"),
                            16,
                        )
                        .map_err(anyhow::Error::from)?;
                        Ok(parsed)
                    },
                )
                .await
                .ok()
            } else {
                crate::utils::rpc::run_with_hydration_pool_retry(
                    &pool,
                    3,
                    "get_storage_at(hydration pool)",
                    move |provider| async move {
                        provider
                            .get_storage_at(address, slot)
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))
                    },
                )
                .await
                .ok()
            };
            if let Some(value) = value_res {
                if !value.is_zero() {
                    out.push((slot, value));
                }
            } else {
                direct_probe_failures = direct_probe_failures.saturating_add(1);
            }
        }
        if direct_probe_failures > 0 {
            anyhow::bail!(
                "fallback storage scan incomplete: {}/{} direct slot probes failed",
                direct_probe_failures,
                direct_probe_attempts
            );
        }
        Ok(out)
    }

    fn storage_scan_use_getproof() -> bool {
        std::env::var("FORKDB_STORAGE_SCAN_USE_GETPROOF")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(true)
    }

    async fn await_global_rpc_cooldown_if_needed() {
        let remaining_ms = crate::utils::rpc::global_rpc_cooldown_remaining_ms();
        if remaining_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(remaining_ms.min(30_000))).await;
        }
    }

    /// Encode a storage slot key as a 32-byte hex string (`0x` + 64 hex chars).
    pub fn storage_key_hex_from_slot(slot: alloy::primitives::U256) -> String {
        format!("0x{}", hex::encode(slot.to_be_bytes::<32>()))
    }

    /// Parse an `eth_getProof` response and extract the `(slot -> value)` map.
    pub fn parse_eth_getproof_storage_values(
        value: &serde_json::Value,
    ) -> anyhow::Result<HashMap<alloy::primitives::U256, alloy::primitives::U256>> {
        let proofs = value
            .get("result")
            .and_then(|v| v.get("storageProof"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow::anyhow!("eth_getProof response missing storageProof array"))?;

        let mut out = HashMap::new();
        for entry in proofs {
            let key = entry.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let val = entry.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if key.is_empty() || val.is_empty() {
                continue;
            }
            let k = alloy::primitives::U256::from_str_radix(key.trim_start_matches("0x"), 16)
                .map_err(|e| anyhow::anyhow!("eth_getProof key parse failed: {e}"))?;
            let v = alloy::primitives::U256::from_str_radix(val.trim_start_matches("0x"), 16)
                .map_err(|e| anyhow::anyhow!("eth_getProof value parse failed: {e}"))?;
            out.insert(k, v);
        }
        Ok(out)
    }

    async fn get_storage_at_via_getproof(
        client: &reqwest::Client,
        rpc_url: &str,
        address: alloy::primitives::Address,
        slots: &[alloy::primitives::U256],
        block_tag: &str,
    ) -> anyhow::Result<HashMap<alloy::primitives::U256, alloy::primitives::U256>> {
        if slots.is_empty() {
            return Ok(HashMap::new());
        }

        let storage_keys = slots
            .iter()
            .map(|slot| alloy::primitives::B256::from(slot.to_be_bytes::<32>()))
            .collect::<Vec<_>>();

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getProof",
            "params": [address, storage_keys, block_tag],
        });

        Self::await_global_rpc_cooldown_if_needed().await;
        let resp = client.post(rpc_url).json(&req).send().await.map_err(|e| {
            let msg = format!("eth_getProof transport error: {e}");
            if crate::utils::rpc::is_rate_limited_rpc_error(&msg) {
                crate::utils::rpc::signal_global_rate_limited_rpc_error();
            }
            anyhow::anyhow!(msg)
        })?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("eth_getProof read error: {e}"))?;
        if !status.is_success() {
            if status.as_u16() == 429 || crate::utils::rpc::is_rate_limited_rpc_error(&body) {
                crate::utils::rpc::signal_global_rate_limited_rpc_error();
            }
            anyhow::bail!("eth_getProof http error: {}", status);
        }
        if crate::utils::rpc::is_rate_limited_rpc_error(&body) {
            crate::utils::rpc::signal_global_rate_limited_rpc_error();
        }
        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("eth_getProof decode error: {e}"))?;
        if let Some(err) = parsed.get("error") {
            let code = err
                .get("code")
                .and_then(|v| v.as_i64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let msg = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("missing error message");
            anyhow::bail!("eth_getProof json-rpc error code {code}: {msg}");
        }
        Self::parse_eth_getproof_storage_values(&parsed)
    }

    async fn batch_get_storage_at_round_robin(
        rpc_urls: &[String],
        address: alloy::primitives::Address,
        slots: &[alloy::primitives::U256],
        block_tag: &str,
    ) -> anyhow::Result<HashMap<alloy::primitives::U256, alloy::primitives::U256>> {
        const BATCH_SIZE: usize = 64;
        const CONCURRENCY: usize = 4;

        if rpc_urls.is_empty() || slots.is_empty() {
            return Ok(HashMap::new());
        }

        let client = Self::shared_http_client().clone();
        let mut in_flight = tokio::task::JoinSet::new();
        let mut out = HashMap::new();
        let slots_shared: Arc<[alloy::primitives::U256]> =
            Arc::from(slots.to_vec().into_boxed_slice());

        for (batch_idx, start) in (0..slots_shared.len()).step_by(BATCH_SIZE).enumerate() {
            while in_flight.len() >= CONCURRENCY {
                if let Some(Ok(Ok(map))) = in_flight.join_next().await {
                    out.extend(map);
                }
            }
            let url = rpc_urls[batch_idx % rpc_urls.len()].clone();
            let client = client.clone();
            let slots = slots_shared.clone();
            let end = start.saturating_add(BATCH_SIZE).min(slots.len());
            let block_tag = block_tag.to_string();

            // Defeating the burst: Pace concurrent requests slightly.
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;

            in_flight.spawn(async move {
                Self::batch_get_storage_at(&client, &url, address, &slots[start..end], &block_tag)
                    .await
            });
        }

        while let Some(done) = in_flight.join_next().await {
            match done {
                Ok(Ok(map)) => out.extend(map),
                Ok(Err(_)) => {}
                Err(_) => {}
            }
        }
        Ok(out)
    }

    async fn batch_get_storage_at(
        client: &reqwest::Client,
        rpc_url: &str,
        address: alloy::primitives::Address,
        slots: &[alloy::primitives::U256],
        block_tag: &str,
    ) -> anyhow::Result<HashMap<alloy::primitives::U256, alloy::primitives::U256>> {
        if slots.is_empty() {
            return Ok(HashMap::new());
        }

        let mut reqs = Vec::with_capacity(slots.len());
        for (i, slot) in slots.iter().enumerate() {
            reqs.push(serde_json::json!({
                "jsonrpc": "2.0",
                "id": (i as u64) + 1,
                "method": "eth_getStorageAt",
                "params": [address, *slot, block_tag],
            }));
        }

        Self::await_global_rpc_cooldown_if_needed().await;
        let resp = client.post(rpc_url).json(&reqs).send().await.map_err(|e| {
            let msg = format!("batch eth_getStorageAt transport error: {e}");
            if crate::utils::rpc::is_rate_limited_rpc_error(&msg) {
                crate::utils::rpc::signal_global_rate_limited_rpc_error();
            }
            anyhow::anyhow!(msg)
        })?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("batch eth_getStorageAt read error: {e}"))?;
        if !status.is_success() {
            if status.as_u16() == 429 || crate::utils::rpc::is_rate_limited_rpc_error(&body) {
                crate::utils::rpc::signal_global_rate_limited_rpc_error();
            }
            anyhow::bail!("batch eth_getStorageAt http error: {}", status);
        }
        if crate::utils::rpc::is_rate_limited_rpc_error(&body) {
            crate::utils::rpc::signal_global_rate_limited_rpc_error();
        }

        let parsed: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("batch decode error: {e}"))?;
        let arr = parsed
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("batch eth_getStorageAt response not array"))?;

        let mut out = HashMap::new();
        let mut seen = vec![false; slots.len()];
        let mut errors = 0usize;
        for item in arr {
            if item.get("error").is_some() {
                errors = errors.saturating_add(1);
                continue;
            }
            let Some(id) = item.get("id").and_then(|v| v.as_u64()) else {
                errors = errors.saturating_add(1);
                continue;
            };
            let result = item.get("result").and_then(|v| v.as_str()).unwrap_or("");
            if id == 0 || result.is_empty() {
                continue;
            }
            let idx = (id as usize).saturating_sub(1);
            if idx >= slots.len() {
                continue;
            }
            let val = match alloy::primitives::U256::from_str_radix(
                result.trim_start_matches("0x"),
                16,
            ) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.insert(slots[idx], val);
            seen[idx] = true;
        }
        let received = seen.iter().filter(|v| **v).count();
        let missing = slots.len().saturating_sub(received);
        let max_missing = (slots.len() / 10).max(2);
        if missing.saturating_add(errors) > max_missing {
            anyhow::bail!(
                "batch eth_getStorageAt incomplete: missing={} errors={} total={}",
                missing,
                errors,
                slots.len()
            );
        }
        Ok(out)
    }

    fn block_on_bridge<T, Fut>(&self, fut: Fut) -> anyhow::Result<T>
    where
        Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        // When we are attached to an ambient multithread runtime, use block_in_place
        // to legally re-enter async from this synchronous DB trait surface.
        if let Ok(current) = tokio::runtime::Handle::try_current() {
            if self.runtime_guard.is_none()
                && current.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
            {
                return tokio::task::block_in_place(|| {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.handle.block_on(fut)
                    })) {
                        Ok(result) => result,
                        Err(_) => Err(anyhow::anyhow!(
                            "fork_db bridge block_on panicked (runtime likely shutting down)"
                        )),
                    }
                });
            }

            // Current-thread runtime cannot call block_in_place and direct block_on panics.
            // Bridge through a dedicated helper thread to avoid per-call thread spawning.
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let job: BridgeJob = Box::new(move || {
                let out = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| {
                        anyhow::anyhow!(
                            "fork_db bridge helper failed to bootstrap local runtime: {}",
                            err
                        )
                    })
                    .and_then(|rt| rt.block_on(fut));
                let _ = tx.send(out);
            });
            match Self::bridge_worker_sender().try_send(job) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    return Err(anyhow::anyhow!(
                        "fork_db bridge queue full; dropping sync bridge call fail-closed"
                    ));
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(anyhow::anyhow!(
                        "fork_db bridge worker unavailable; dropping sync bridge call fail-closed"
                    ));
                }
            }
            return match rx
                .recv_timeout(std::time::Duration::from_millis(Self::bridge_timeout_ms()))
            {
                Ok(result) => result,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                    "fork_db bridge helper thread timed out after {}ms",
                    Self::bridge_timeout_ms()
                )),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                    "fork_db bridge helper thread terminated unexpectedly before returning"
                )),
            };
        }

        // Private runtime path (or no ambient runtime): direct blocking is valid.
        self.handle.block_on(fut)
    }

    /// Scans the storage of a contract to find all non-zero slots.
    /// Uses `debug_storageRangeAt` if available, or falls back to common patterns.
    pub fn scan_storage(
        &self,
        address: alloy::primitives::Address,
        max_slots: usize,
    ) -> anyhow::Result<Vec<(alloy::primitives::U256, alloy::primitives::U256)>> {
        let pool = self.pool.clone();
        let rpc_urls = self.rpc_urls.clone();
        let block_number = self.block_number;
        let max_slots = max_slots.clamp(1, 10_000);
        let block_hash_cache = self.block_hash_cache.clone();
        let debug_storage_range_mode = self.debug_storage_range_mode.clone();
        self.block_on_bridge(async move {
            if debug_storage_range_mode.load(Ordering::Relaxed) == DEBUG_STORAGE_MODE_UNSUPPORTED {
                return Self::scan_storage_fallback_async(
                    pool,
                    rpc_urls,
                    address,
                    max_slots,
                    block_number,
                )
                .await;
            }

            let mut results = Vec::new();
            let mut current_key =
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
            let mut total_slots = 0;
            let safe_entry_limit = max_slots; // Hard cap to prevent infinite loops

            // `debug_storageRangeAt` requires a block hash, not a block number/tag.
            // Fetch once per scan to avoid repeated failures and extra RPC.
            let block_hash = match block_number {
                Some(n) => {
                    if let Some(hit) = block_hash_cache.get(&n) {
                        *hit
                    } else {
                        match Self::fetch_block_hash_at(pool.clone(), n).await {
                            Ok(h) => {
                                block_hash_cache.insert(n, h);
                                Self::trim_block_hash_cache(&block_hash_cache);
                                h
                            }
                            Err(_err) => {
                                // If we cannot resolve a block hash for a pinned scan, fail over.
                                return Self::scan_storage_fallback_async(
                                    pool,
                                    rpc_urls,
                                    address,
                                    max_slots,
                                    block_number,
                                )
                                .await;
                            }
                        }
                    }
                }
                None => {
                    // Latest path: resolve the latest block number first, then its hash.
                    let latest = match crate::utils::rpc::run_with_hydration_pool_retry(
                        &pool,
                        3,
                        "get_block_number(hydration pool)",
                        move |provider| async move {
                            provider
                                .get_block_number()
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))
                        },
                    )
                    .await
                    {
                        Ok(n) => n,
                        Err(_) => {
                            return Self::scan_storage_fallback_async(
                                pool,
                                rpc_urls,
                                address,
                                max_slots,
                                block_number,
                            )
                            .await;
                        }
                    };
                    let latest_u64: u64 = latest;
                    if let Some(hit) = block_hash_cache.get(&latest_u64) {
                        *hit
                    } else {
                        match Self::fetch_block_hash_at(pool.clone(), latest_u64).await {
                            Ok(h) => {
                                block_hash_cache.insert(latest_u64, h);
                                Self::trim_block_hash_cache(&block_hash_cache);
                                h
                            }
                            Err(_) => {
                                return Self::scan_storage_fallback_async(
                                    pool,
                                    rpc_urls,
                                    address,
                                    max_slots,
                                    block_number,
                                )
                                .await;
                            }
                        }
                    }
                }
            };
            let block_hash_hex = format!("0x{}", hex::encode(block_hash.as_slice()));

            loop {
                if total_slots >= safe_entry_limit {
                    break;
                }

                let params = serde_json::json!([
                    block_hash_hex.as_str(),
                    0,
                    address,
                    current_key,
                    1000 // Batch size
                ]);

                match crate::utils::rpc::run_with_hydration_pool_retry(
                    &pool,
                    3,
                    "debug_storageRangeAt(hydration pool)",
                    move |provider| {
                        let params = params.clone();
                        async move {
                            provider
                                .raw_request::<serde_json::Value, serde_json::Value>(
                                    std::borrow::Cow::Borrowed("debug_storageRangeAt"),
                                    params,
                                )
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))
                        }
                    },
                )
                    .await
                {
                    Ok(response) => {
                        debug_storage_range_mode
                            .store(DEBUG_STORAGE_MODE_SUPPORTED, Ordering::Relaxed);
                        if let Some(storage_map) = response.get("storage").and_then(|s| s.as_object()) {
                            if storage_map.is_empty() {
                                break;
                            }

                            for (_, entry) in storage_map {
                                if total_slots >= safe_entry_limit {
                                    break;
                                }
                                let key_str = entry.get("key").and_then(|v| v.as_str());
                                let val_str = entry.get("value").and_then(|v| v.as_str());

                                if let (Some(k), Some(v)) = (key_str, val_str) {
                                    let k_u256 = match alloy::primitives::U256::from_str_radix(
                                        k.trim_start_matches("0x"),
                                        16,
                                    ) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                    let v_u256 = match alloy::primitives::U256::from_str_radix(
                                        v.trim_start_matches("0x"),
                                        16,
                                    ) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                    if !v_u256.is_zero() {
                                        results.push((k_u256, v_u256));
                                        total_slots += 1;
                                    }
                                }
                            }

                            // Pagination Logic
                            if let Some(next) = response.get("nextKey").and_then(|v| v.as_str()) {
                                if next
                                    == "0x0000000000000000000000000000000000000000000000000000000000000000"
                                    || next == "null"
                                {
                                    break;
                                }
                                current_key = next.to_string();
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    Err(err) => {
                        // If the first request fails, fail over to sparse fallback probing.
                        // If a later page fails, merge with sparse fallback to reduce partial-state risk.
                        if results.is_empty() {
                            let err = Self::compact_error(err);
                            if Self::debug_storage_unavailable(&err) {
                                debug_storage_range_mode
                                    .store(DEBUG_STORAGE_MODE_UNSUPPORTED, Ordering::Relaxed);
                            }
                            return Self::scan_storage_fallback_async(
                                pool,
                                rpc_urls,
                                address,
                                max_slots,
                                block_number,
                            )
                            .await;
                        }
                        let fallback = Self::scan_storage_fallback_async(
                            pool.clone(),
                            rpc_urls.clone(),
                            address,
                            max_slots,
                            block_number,
                        )
                        .await?;
                        let mut seen = std::collections::HashSet::new();
                        for (k, _) in &results {
                            seen.insert(*k);
                        }
                        for (k, v) in fallback {
                            if results.len() >= safe_entry_limit {
                                break;
                            }
                            if seen.insert(k) {
                                results.push((k, v));
                            }
                        }
                        break;
                    }
                }
            }

            Ok(results)
        })
    }
}

impl DatabaseRef for ForkDB {
    type Error = anyhow::Error;

    fn basic_ref(&self, address: rAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let addr = alloy::primitives::Address::from_slice(address.as_slice());
        let pool = self.pool.clone();
        let pinned_block = self.block_number;
        let code_by_hash_cache = self.code_by_hash_cache.clone();
        let account_info_cache = self.account_info_cache.clone();
        let cache_key = pinned_block.map(|block| (addr, block));

        if let Some(key) = cache_key {
            if let Some(hit) = account_info_cache.get(&key) {
                return Ok(hit.value().clone());
            }
        }

        self.block_on_bridge(async move {
            let balance_pool = pool.clone();
            let code_pool = pool.clone();
            let nonce_pool = pool.clone();

            let balance_fut = async move {
                if let Some(block_number) = pinned_block {
                    crate::utils::rpc::run_with_hydration_pool_retry(
                        &balance_pool,
                        5,
                        "eth_getBalance(hydration pool)",
                        move |provider| async move {
                            let raw: String = provider
                                .raw_request(
                                    std::borrow::Cow::Borrowed("eth_getBalance"),
                                    serde_json::json!([addr, format!("0x{block_number:x}")]),
                                )
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))?;
                            let parsed = alloy::primitives::U256::from_str_radix(
                                raw.trim_start_matches("0x"),
                                16,
                            )
                            .map_err(anyhow::Error::from)?;
                            Ok(parsed)
                        },
                    )
                    .await
                } else {
                    crate::utils::rpc::run_with_hydration_pool_retry(
                        &balance_pool,
                        5,
                        "get_balance(hydration pool)",
                        move |provider| async move {
                            provider
                                .get_balance(addr)
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))
                        },
                    )
                    .await
                }
            };

            let code_fut = async move {
                if let Some(block_number) = pinned_block {
                    crate::utils::rpc::run_with_hydration_pool_retry(
                        &code_pool,
                        5,
                        "eth_getCode(hydration pool)",
                        move |provider| async move {
                            let raw: String = provider
                                .raw_request(
                                    std::borrow::Cow::Borrowed("eth_getCode"),
                                    serde_json::json!([addr, format!("0x{block_number:x}")]),
                                )
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))?;
                            let trimmed = raw.trim_start_matches("0x");
                            let bytes = hex::decode(trimmed).map_err(anyhow::Error::from)?;
                            Ok(bytes)
                        },
                    )
                    .await
                } else {
                    crate::utils::rpc::run_with_hydration_pool_retry(
                        &code_pool,
                        5,
                        "get_code_at(hydration pool)",
                        move |provider| async move {
                            let code = provider
                                .get_code_at(addr)
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))?;
                            Ok(code.to_vec())
                        },
                    )
                    .await
                }
            };

            let nonce_fut = async move {
                if let Some(block_number) = pinned_block {
                    crate::utils::rpc::run_with_hydration_pool_retry(
                        &nonce_pool,
                        5,
                        "eth_getTransactionCount(hydration pool)",
                        move |provider| async move {
                            let raw: String = provider
                                .raw_request(
                                    std::borrow::Cow::Borrowed("eth_getTransactionCount"),
                                    serde_json::json!([addr, format!("0x{block_number:x}")]),
                                )
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))?;
                            let nonce = u64::from_str_radix(raw.trim_start_matches("0x"), 16)
                                .map_err(anyhow::Error::from)?;
                            Ok(nonce)
                        },
                    )
                    .await
                } else {
                    crate::utils::rpc::run_with_hydration_pool_retry(
                        &nonce_pool,
                        5,
                        "get_transaction_count(hydration pool)",
                        move |provider| async move {
                            provider
                                .get_transaction_count(addr)
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))
                        },
                    )
                    .await
                }
            };

            let (balance, code, nonce) = tokio::try_join!(balance_fut, code_fut, nonce_fut)?;
            let r_balance = rU256::from_be_bytes(balance.to_be_bytes::<32>());

            if nonce == 0 && r_balance.is_zero() && code.is_empty() {
                if let Some(key) = cache_key {
                    account_info_cache.insert(key, None);
                    Self::trim_account_info_cache(&account_info_cache);
                }
                return Ok(None);
            }

            let bytecode = Bytecode::new_raw(rBytes::from(code));
            let code_hash = bytecode.hash_slow();
            code_by_hash_cache.insert(code_hash, bytecode.clone());
            let account = Some(AccountInfo::new(r_balance, nonce, code_hash, bytecode));

            if let Some(key) = cache_key {
                account_info_cache.insert(key, account.clone());
                Self::trim_account_info_cache(&account_info_cache);
            }
            Ok(account)
        })
    }

    fn code_by_hash_ref(&self, code_hash: revm::primitives::B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_cache
            .get(&code_hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow::anyhow!("missing bytecode for code hash {}", code_hash))
    }

    fn storage_ref(&self, address: rAddress, index: rU256) -> Result<rU256, Self::Error> {
        let addr = alloy::primitives::Address::from_slice(address.as_slice());
        let idx = alloy::primitives::U256::from_be_bytes(index.to_be_bytes::<32>());
        let pool = self.pool.clone();
        let pinned_block = self.block_number;
        let storage_cache = self.storage_cache.clone();

        if let Some(block_number) = pinned_block {
            if let Some(hit) = storage_cache.get(&(addr, idx, block_number)) {
                return Ok(rU256::from_be_bytes(hit.to_be_bytes::<32>()));
            }
        }

        self.block_on_bridge(async move {
            let val = if let Some(block_number) = pinned_block {
                crate::utils::rpc::run_with_hydration_pool_retry(
                    &pool,
                    5,
                    "eth_getStorageAt(hydration pool)",
                    move |provider| async move {
                        let raw: String = provider
                            .raw_request(
                                std::borrow::Cow::Borrowed("eth_getStorageAt"),
                                serde_json::json!([addr, idx, format!("0x{block_number:x}")]),
                            )
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        let parsed = alloy::primitives::U256::from_str_radix(
                            raw.trim_start_matches("0x"),
                            16,
                        )
                        .map_err(anyhow::Error::from)?;
                        Ok(parsed)
                    },
                )
                .await?
            } else {
                crate::utils::rpc::run_with_hydration_pool_retry(
                    &pool,
                    5,
                    "get_storage_at(hydration pool)",
                    move |provider| async move {
                        provider
                            .get_storage_at(addr, idx)
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))
                    },
                )
                .await?
            };
            if let Some(block_number) = pinned_block {
                storage_cache.insert((addr, idx, block_number), val);
                Self::trim_storage_cache(&storage_cache);
            }
            Ok(rU256::from_be_bytes(val.to_be_bytes::<32>()))
        })
    }

    fn block_hash_ref(&self, number: u64) -> Result<revm::primitives::B256, Self::Error> {
        let reference_head = if let Some(pinned) = self.block_number {
            pinned
        } else {
            let pool = self.pool.clone();
            self.block_on_bridge(async move {
                let provider = pool.primary();
                provider
                    .get_block_number()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
            })?
        };
        if number >= reference_head || reference_head.saturating_sub(number) > 256 {
            return Ok(revm::primitives::B256::ZERO);
        }

        if let Some(hit) = self.block_hash_cache.get(&number) {
            return Ok(*hit);
        }
        let pool = self.pool.clone();
        let hash =
            self.block_on_bridge(async move { Self::fetch_block_hash_at(pool, number).await })?;
        self.block_hash_cache.insert(number, hash);
        Self::trim_block_hash_cache(&self.block_hash_cache);
        Ok(hash)
    }
}

impl Database for ForkDB {
    type Error = anyhow::Error;

    fn basic(&mut self, address: rAddress) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: revm::primitives::B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: rAddress, index: rU256) -> Result<rU256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<revm::primitives::B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_abi_address_array, ForkDB, DEBUG_STORAGE_MODE_UNKNOWN,
        DEBUG_STORAGE_MODE_UNSUPPORTED,
    };
    use alloy::primitives::U256;
    use revm::primitives::B256;
    use revm::DatabaseRef;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_discover_storage_slots_from_bytecode_finds_static_sload_sstore_slots() {
        // PUSH1 0x07; SLOAD; PUSH2 0x01 0x23; SSTORE
        let bytecode = [0x60, 0x07, 0x54, 0x61, 0x01, 0x23, 0x55];
        let slots = ForkDB::discover_storage_slots_from_bytecode(&bytecode, 16);
        assert!(slots.contains(&U256::from(7u64)));
        assert!(slots.contains(&U256::from(0x0123u64)));
    }

    #[test]
    fn test_discover_storage_slots_tracks_dup_swap_and_keccak_seed_patterns() {
        // PUSH1 0x2a; DUP1; SLOAD
        // PUSH1 0x40; PUSH1 0x20; SHA3; SLOAD
        let bytecode = [
            0x60, 0x2a, 0x80, 0x54, // slot 0x2a via DUP1 + SLOAD
            0x60, 0x40, 0x60, 0x20, 0x20, 0x54, // keccak seed candidate slot 0x40
        ];
        let slots = ForkDB::discover_storage_slots_from_bytecode(&bytecode, 16);
        assert!(slots.contains(&U256::from(0x2au64)));
        assert!(slots.contains(&U256::from(0x40u64)));
    }

    #[test]
    fn test_fallback_storage_slots_cover_common_range_and_discovered_slots() {
        let discovered = vec![U256::from(0xdeadbeefu64), U256::from(5u64)];
        let slots = ForkDB::fallback_storage_slots(110, &discovered);

        assert!(slots.contains(&U256::from(0u64)));
        assert!(slots.contains(&U256::from(100u64)));
        assert!(slots.contains(&U256::from(0xdeadbeefu64)));

        let occurrences = slots.iter().filter(|v| **v == U256::from(5u64)).count();
        assert_eq!(
            occurrences, 1,
            "fallback slots must deduplicate repeated entries"
        );
    }

    #[test]
    fn test_debug_storage_unavailable_only_for_method_not_found_class() {
        assert!(ForkDB::debug_storage_unavailable(
            "rpc error: method not found"
        ));
        assert!(ForkDB::debug_storage_unavailable(
            "json-rpc error code -32601"
        ));
        assert!(!ForkDB::debug_storage_unavailable(
            "json-rpc error code -32602 invalid params"
        ));
        assert!(!ForkDB::debug_storage_unavailable("unknown block"));
    }

    #[test]
    fn test_decode_abi_address_array_rejects_out_of_bounds_without_default_zero_words() {
        let mut payload = vec![0u8; 64];
        payload[31] = 0x20;
        payload[63] = 0x02;
        let decoded = decode_abi_address_array(&payload, 8);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_block_hash_ref_respects_evm_window_for_pinned_head() {
        let db = ForkDB::with_block_number("http://127.0.0.1:8545", 1_000).expect("forkdb");
        let current = <ForkDB as DatabaseRef>::block_hash_ref(&db, 1_000).expect("current block");
        assert_eq!(current, B256::ZERO);

        let too_old = <ForkDB as DatabaseRef>::block_hash_ref(&db, 743).expect("too old block");
        assert_eq!(too_old, B256::ZERO);
    }

    #[test]
    fn test_code_by_hash_ref_missing_hash_fails_closed() {
        let db = ForkDB::with_block_number("http://127.0.0.1:8545", 1_000).expect("forkdb");
        let result = <ForkDB as DatabaseRef>::code_by_hash_ref(&db, B256::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_storage_mode_is_instance_local() {
        let db_a = ForkDB::with_block_number("http://127.0.0.1:8545", 1_000).expect("forkdb a");
        let db_b = ForkDB::with_block_number("http://127.0.0.1:8545", 1_000).expect("forkdb b");

        db_a.debug_storage_range_mode
            .store(DEBUG_STORAGE_MODE_UNSUPPORTED, Ordering::Relaxed);

        assert_eq!(
            db_a.debug_storage_range_mode.load(Ordering::Relaxed),
            DEBUG_STORAGE_MODE_UNSUPPORTED
        );
        assert_eq!(
            db_b.debug_storage_range_mode.load(Ordering::Relaxed),
            DEBUG_STORAGE_MODE_UNKNOWN
        );
    }
}
