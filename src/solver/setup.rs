use crate::fork_db::ForkDB;
use crate::storage::contracts_db::{BytecodeSlice, ContractsDb};
use crate::symbolic::state::SymbolicMachine;
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use dashmap::DashMap;
use revm::db::CacheDB;
use revm::primitives::{AccountInfo, Address, Bytecode, Bytes, U256};
use revm::DatabaseRef;
use std::cell::RefCell;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use z3::ast::{Ast, BV};
use z3::{Context, Solver};

/// Canonical sentinel addresses used across all objectives.
pub const ATTACKER: Address = Address::new([0xAA; 20]);
pub const TARGET: Address = Address::new([0xBB; 20]);
static STORAGE_SCAN_WARN_COUNT: AtomicU64 = AtomicU64::new(0);
static DEPENDENCY_STORAGE_SCAN_WARN_COUNT: AtomicU64 = AtomicU64::new(0);
const STORAGE_SCAN_LIMIT: usize = 1024;
const DEFAULT_CONTRACT_BALANCE_ETH: u64 = 100;
const TOKEN_BALANCE_CALL_TIMEOUT_MS: u64 = 250;
const DEFAULT_DEEP_SCAN_PRELOADER_STORAGE_LIMIT: usize = 16_384;

#[derive(Clone, Debug)]
struct DeepScanPreloadedState {
    bytecode: Bytes,
    account_info: AccountInfo,
    storage_slots: Vec<(U256, U256)>,
    storage_scan_succeeded: bool,
    remote_balance: Option<U256>,
}

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

#[derive(Clone, Debug)]
pub struct DependencyContext {
    pub address: Address,
    pub account_info: AccountInfo,
    pub storage_slots: Vec<(U256, U256)>,
}

#[derive(Clone, Debug)]
pub struct TargetContext {
    pub target_address: Address,
    /// Strict empty-state marker for scanner-discovered targets.
    /// If true, the target has no code/balance/storage at hydration time and must be treated as
    /// `ZERO_STATE` to prevent phantom-liquidity false positives.
    pub zero_state: bool,
    pub account_info: AccountInfo,
    pub storage_slots: Vec<(U256, U256)>,
    pub attacker_token_balances: Vec<(Address, U256)>,
    pub selectors: Vec<Bytes>,
    pub nft_callback_selectors: Vec<Bytes>,
    pub dead_end_pcs: HashSet<usize>,
    pub dependencies: Vec<DependencyContext>,
}

thread_local! {
    static ACTIVE_TARGET_CONTEXT: RefCell<Option<Arc<TargetContext>>> = const { RefCell::new(None) };
}

pub struct TargetContextScopeGuard {
    previous: Option<Arc<TargetContext>>,
}

impl Drop for TargetContextScopeGuard {
    fn drop(&mut self) {
        ACTIVE_TARGET_CONTEXT.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}

pub fn enter_target_context(context: Arc<TargetContext>) -> TargetContextScopeGuard {
    let previous = ACTIVE_TARGET_CONTEXT.with(|slot| slot.replace(Some(context)));
    TargetContextScopeGuard { previous }
}

pub fn current_target_context() -> Option<Arc<TargetContext>> {
    ACTIVE_TARGET_CONTEXT.with(|slot| slot.borrow().as_ref().map(Arc::clone))
}

/// Strict "empty state" classifier used for zero-hydration verification.
///
/// A target is considered `ZERO_STATE` iff:
/// - bytecode is empty, AND
/// - remote ETH balance is zero (or account is non-existent), AND
/// - storage scan succeeded and found no non-zero slots.
///
/// This intentionally fails closed when storage cannot be scanned.
pub fn compute_zero_state_flag(
    bytecode: &revm::primitives::Bytes,
    remote_balance: Option<U256>,
    storage_slots: &[(U256, U256)],
    storage_scan_succeeded: bool,
) -> bool {
    if !storage_scan_succeeded {
        return false;
    }
    if !bytecode.is_empty() {
        return false;
    }
    if !storage_slots.is_empty() {
        return false;
    }
    remote_balance.unwrap_or(U256::MAX).is_zero()
}

pub fn selectors_from_context_or_scan(bytecode: &Bytes) -> Vec<Bytes> {
    if let Some(ctx) = current_target_context() {
        return ctx.selectors.clone();
    }
    crate::solver::heuristics::scan_for_state_changing_selectors(bytecode)
}

pub fn nft_callback_selectors_from_context_or_scan(bytecode: &Bytes) -> Vec<Bytes> {
    if let Some(ctx) = current_target_context() {
        return ctx.nft_callback_selectors.clone();
    }
    crate::solver::heuristics::scan_for_nft_callback_selectors(bytecode)
}

fn scan_bytecode_slice(bytecode: &Bytes) -> BytecodeSlice {
    BytecodeSlice {
        selectors: crate::solver::heuristics::scan_for_state_changing_selectors(bytecode),
        nft_callback_selectors: crate::solver::heuristics::scan_for_nft_callback_selectors(
            bytecode,
        ),
        dead_end_pcs: crate::solver::heuristics::scan_dead_end_pcs(bytecode),
    }
}

fn merge_bytecode_slices(mut base: BytecodeSlice, other: BytecodeSlice) -> BytecodeSlice {
    base.selectors.extend(other.selectors);
    base.nft_callback_selectors
        .extend(other.nft_callback_selectors);
    base.dead_end_pcs.extend(other.dead_end_pcs);
    base.selectors.sort();
    base.selectors.dedup();
    base.nft_callback_selectors.sort();
    base.nft_callback_selectors.dedup();
    base
}

fn hydrate_bytecode_slice(contracts_db: Option<&ContractsDb>, bytecode: &Bytes) -> BytecodeSlice {
    let bytecode_hash = Bytecode::new_raw(bytecode.clone()).hash_slow();
    if let Some(db) = contracts_db {
        if let Ok(Some(cached)) = db.lookup_bytecode_slice(bytecode_hash) {
            return cached;
        }
    }

    if let Some(db) = contracts_db {
        let simhash = crate::storage::simhash::simhash64(bytecode.as_ref());
        let _ = db.upsert_bytecode_simhash(bytecode_hash, simhash, bytecode.len());
        if simhash_classification_enabled() {
            let max_hamming = simhash_max_hamming();
            let max_len_delta = simhash_max_len_delta();
            let candidate_limit = simhash_candidate_limit();
            if let Ok(Some((_template_hash, slice))) = db.lookup_similar_bytecode_slice_by_simhash(
                simhash,
                bytecode.len(),
                max_hamming,
                max_len_delta,
                candidate_limit,
            ) {
                // Promote the reused slice to an exact hash entry so future lookups are O(1).
                if let Err(err) = db.upsert_bytecode_slice(bytecode_hash, &slice) {
                    eprintln!(
                        "[WARN] SimHash slice promotion failed for hash {:#x}: {}",
                        bytecode_hash, err
                    );
                }
                return slice;
            }
        }
    }

    let sliced = scan_bytecode_slice(bytecode);
    if let Some(db) = contracts_db {
        if let Err(err) = db.upsert_bytecode_slice(bytecode_hash, &sliced) {
            eprintln!(
                "[WARN] Bytecode slice cache write failed for hash {:#x}: {}",
                bytecode_hash, err
            );
        }
        let simhash = crate::storage::simhash::simhash64(bytecode.as_ref());
        let _ = db.upsert_bytecode_simhash(bytecode_hash, simhash, bytecode.len());
    }
    sliced
}

fn default_contract_balance() -> U256 {
    U256::from(DEFAULT_CONTRACT_BALANCE_ETH) * U256::from(10).pow(U256::from(18))
}

fn default_account_info(bytecode: &revm::primitives::Bytes) -> AccountInfo {
    let code_obj = Bytecode::new_raw(bytecode.clone());
    AccountInfo::new(
        default_contract_balance(),
        1,
        code_obj.hash_slow(),
        code_obj,
    )
}

fn proxy_resolution_enabled() -> bool {
    std::env::var("PROXY_RESOLUTION_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn proxy_resolution_max_depth() -> usize {
    std::env::var("PROXY_RESOLUTION_MAX_DEPTH")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, 5))
        .unwrap_or(3)
}

fn proxy_resolution_diamond_max_facets() -> usize {
    std::env::var("PROXY_RESOLUTION_DIAMOND_MAX_FACETS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(0, 32))
        .unwrap_or(12)
}

fn simhash_classification_enabled() -> bool {
    std::env::var("SIMHASH_CLASSIFICATION_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn simhash_max_hamming() -> u32 {
    std::env::var("SIMHASH_MAX_HAMMING")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .map(|v| v.clamp(0, 32))
        .unwrap_or(3)
}

fn simhash_max_len_delta() -> usize {
    std::env::var("SIMHASH_MAX_LEN_DELTA")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.min(16 * 1024))
        .unwrap_or(64)
}

fn simhash_candidate_limit() -> usize {
    std::env::var("SIMHASH_CANDIDATE_LIMIT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(1, 2_000))
        .unwrap_or(128)
}

fn deep_scan_preloader_storage_limit() -> usize {
    std::env::var("DEEP_SCAN_PRELOADER_STORAGE_LIMIT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(64, 65_536))
        .unwrap_or(DEFAULT_DEEP_SCAN_PRELOADER_STORAGE_LIMIT)
}

fn deep_scan_preloader_state_cache() -> &'static DashMap<Address, DeepScanPreloadedState> {
    static CACHE: OnceLock<DashMap<Address, DeepScanPreloadedState>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
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
    let mut out = std::env::var("PROFIT_TRACK_TOKENS")
        .ok()
        .map(|raw| parse_address_csv(&raw))
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

pub fn preload_profit_tracking_state(
    rpc_url: &str,
    contracts_db: Option<&ContractsDb>,
) -> anyhow::Result<usize> {
    let tracked = load_profit_tracking_tokens();
    if tracked.is_empty() {
        return Ok(0);
    }

    let storage_limit = deep_scan_preloader_storage_limit();
    let fork_db = ForkDB::new(rpc_url)?;
    let cache = deep_scan_preloader_state_cache();
    let mut loaded = 0usize;

    for token in tracked {
        let remote = match fork_db.basic_ref(token) {
            Ok(Some(info)) => Some(info),
            Ok(None) => None,
            Err(err) => {
                eprintln!(
                    "[WARN] [DEEP-SCAN] Failed to preload basic info for {:#x}: {}",
                    token, err
                );
                None
            }
        };

        let mut bytecode = Bytes::new();
        let mut account_info = AccountInfo::new(U256::ZERO, 0, Default::default(), Bytecode::new());
        let mut remote_balance = Some(U256::ZERO);
        if let Some(mut info) = remote {
            if let Some(code) = info.code.as_ref() {
                bytecode = code.bytes();
            }
            let code_obj = Bytecode::new_raw(bytecode.clone());
            info.code_hash = code_obj.hash_slow();
            info.code = Some(code_obj);
            remote_balance = Some(info.balance);
            account_info = info;
        } else if !bytecode.is_empty() {
            let code_obj = Bytecode::new_raw(bytecode.clone());
            account_info = AccountInfo::new(U256::ZERO, 0, code_obj.hash_slow(), code_obj);
        }

        let (storage_slots, storage_scan_succeeded) =
            match fork_db.scan_storage(token, storage_limit) {
                Ok(slots) => (slots, true),
                Err(err) => {
                    eprintln!(
                        "[WARN] [DEEP-SCAN] Storage preload failed for {:#x}: {}",
                        token, err
                    );
                    (Vec::new(), false)
                }
            };

        if contracts_db.is_some() && !bytecode.is_empty() {
            let _ = hydrate_bytecode_slice(contracts_db, &bytecode);
        }

        cache.insert(
            token,
            DeepScanPreloadedState {
                bytecode,
                account_info,
                storage_slots,
                storage_scan_succeeded,
                remote_balance,
            },
        );
        loaded = loaded.saturating_add(1);
    }

    Ok(loaded)
}

fn bytecode_looks_like_proxy(bytecode: &Bytes) -> bool {
    // Minimal heuristic: proxies must DELEGATECALL.
    bytecode.contains(&0xf4)
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

fn decode_address_from_abi_word(word: &[u8]) -> Option<Address> {
    if word.len() < 32 {
        return None;
    }
    let addr = Address::from_slice(&word[12..32]);
    if addr == Address::ZERO {
        None
    } else {
        Some(addr)
    }
}

fn scan_storage_with_warning(fork_db: &ForkDB, contract_addr: Address) -> Vec<(U256, U256)> {
    match fork_db.scan_storage(contract_addr, STORAGE_SCAN_LIMIT) {
        Ok(scanned_slots) => {
            if !scanned_slots.is_empty() {
                println!(
                    "[Scan] Found {} storage slots for contract {:?}",
                    scanned_slots.len(),
                    contract_addr
                );
            }
            scanned_slots
        }
        Err(e) => {
            let count = STORAGE_SCAN_WARN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if count == 1 {
                println!(
                    "[Scan] Warning: Storage scan failed: {}. Continuing with sparse fallback-derived storage snapshot.",
                    e
                );
                println!("[Scan] Warning: Repeated storage scan errors will be suppressed.");
            } else if count.is_multiple_of(100) {
                println!(
                    "[Scan] Warning: Suppressed {} repeated storage scan warnings.",
                    count - 1
                );
            }
            Vec::new()
        }
    }
}

fn discover_candidate_tokens(
    chain_id: u64,
    bytecode: &revm::primitives::Bytes,
    attacker: Address,
    contract_addr: Address,
) -> Vec<Address> {
    let chain_config = crate::config::chains::ChainConfig::get(chain_id);
    let mut tokens = chain_config.known_tokens;
    let excludes = vec![attacker, contract_addr];
    for token in crate::solver::heuristics::scan_for_tokens(bytecode, &excludes) {
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    tokens
}

fn local_context_expansion_enabled() -> bool {
    std::env::var("LOCAL_CONTEXT_EXPANSION_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn local_context_dependency_max() -> usize {
    std::env::var("LOCAL_CONTEXT_DEP_MAX")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(0, 10))
        .unwrap_or(8)
}

fn local_context_dependency_storage_scan_limit() -> usize {
    std::env::var("LOCAL_CONTEXT_DEP_STORAGE_SCAN_LIMIT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(0, 256))
        .unwrap_or(0)
}

fn modeling_chain_id() -> anyhow::Result<u64> {
    match std::env::var("CHAIN_ID") {
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("CHAIN_ID must be a valid u64, got `{}`", raw.trim())),
        Err(_) if cfg!(test) => Ok(8453),
        Err(_) => Err(anyhow::anyhow!(
            "CHAIN_ID is required for solver modeling; refusing implicit chain fallback."
        )),
    }
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

fn discover_immediate_dependencies(
    bytecode: &Bytes,
    excludes: &[Address],
    max: usize,
) -> Vec<Address> {
    let mut out = Vec::new();
    if max == 0 {
        return out;
    }
    for candidate in crate::solver::heuristics::scan_for_tokens(bytecode, excludes) {
        if candidate == Address::ZERO || is_precompile_address(candidate) {
            continue;
        }
        if out.contains(&candidate) {
            continue;
        }
        out.push(candidate);
        if out.len() >= max {
            break;
        }
    }
    out
}

fn multicall3_address() -> Address {
    alloy::primitives::address!("cA11bde05977b3631167028862bE2a173976CA11")
}

fn balance_of_calldata(owner: Address) -> Vec<u8> {
    let mut addr_word = [0u8; 32];
    addr_word[12..].copy_from_slice(owner.as_slice());
    let mut call_data = vec![0x70, 0xa0, 0x82, 0x31];
    call_data.extend_from_slice(&addr_word);
    call_data
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
    let decoded =
        <aggregate3Call as alloy::sol_types::SolCall>::abi_decode_returns(return_bytes, true)
            .ok()?;
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

async fn fetch_attacker_token_balances_multicall_async(
    provider: alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
    tokens: &[Address],
    attacker: Address,
) -> Option<Vec<(Address, U256)>> {
    if tokens.is_empty() {
        return Some(Vec::new());
    }

    let call_data = balance_of_calldata(attacker);
    let calls = tokens
        .iter()
        .map(|token| Multicall3Call {
            target: alloy::primitives::Address::from(token.into_array()),
            allowFailure: true,
            callData: call_data.clone().into(),
        })
        .collect::<Vec<_>>();
    let request = alloy::rpc::types::TransactionRequest::default()
        .to(multicall3_address())
        .input(alloy::rpc::types::TransactionInput::new(
            aggregate3Call { calls }.abi_encode().into(),
        ));

    let raw = tokio::time::timeout(
        std::time::Duration::from_millis(TOKEN_BALANCE_CALL_TIMEOUT_MS),
        provider.call(&request),
    )
    .await
    .ok()?
    .ok()?;
    decode_multicall_balance_results(tokens, raw.as_ref())
}

fn fetch_attacker_token_balances(
    rpc_url: Option<&str>,
    tokens: &[Address],
    attacker: Address,
) -> Vec<(Address, U256)> {
    let provider = rpc_url
        .and_then(|url| url.parse().ok())
        .map(|parsed| alloy::providers::ProviderBuilder::new().on_http(parsed));
    let current_handle = tokio::runtime::Handle::try_current().ok();
    let owned_runtime = if current_handle.is_none() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .ok()
    } else {
        None
    };
    let rt_handle = current_handle.or_else(|| owned_runtime.as_ref().map(|rt| rt.handle().clone()));
    let runtime_flavor = tokio::runtime::Handle::try_current()
        .ok()
        .map(|handle| handle.runtime_flavor());
    let use_block_in_place = matches!(
        runtime_flavor,
        Some(tokio::runtime::RuntimeFlavor::MultiThread)
    );
    let use_thread_bridge = matches!(
        runtime_flavor,
        Some(tokio::runtime::RuntimeFlavor::CurrentThread)
    );

    if let (Some(provider), Some(rt)) = (provider.as_ref(), rt_handle.as_ref()) {
        let provider = provider.clone();
        let tokens = tokens.to_vec();
        let fetch = async move {
            fetch_attacker_token_balances_multicall_async(provider, &tokens, attacker).await
        };
        let multicall_result = if use_block_in_place {
            tokio::task::block_in_place(|| rt.block_on(fetch))
        } else if use_thread_bridge {
            let rt = rt.clone();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let _ = tx.send(rt.block_on(fetch));
            });
            rx.recv().ok().flatten()
        } else {
            rt.block_on(fetch)
        };
        if let Some(result) = multicall_result {
            return result;
        }
    }

    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let attacker_bal_u256 =
            if let (Some(provider), Some(rt)) = (provider.as_ref(), rt_handle.as_ref()) {
                let provider = provider.clone();
                let token = *token;
                let fetch = async move {
                    let req = alloy::rpc::types::TransactionRequest::default()
                        .to(alloy::primitives::Address::from(token.into_array()))
                        .input(alloy::rpc::types::TransactionInput::new(
                            balance_of_calldata(attacker).into(),
                        ));

                    match tokio::time::timeout(
                        std::time::Duration::from_millis(TOKEN_BALANCE_CALL_TIMEOUT_MS),
                        provider.call(&req),
                    )
                    .await
                    {
                        Ok(Ok(bytes)) => alloy::primitives::U256::from_be_bytes::<32>(
                            decode_balance_word(bytes.as_ref()).to_be_bytes::<32>(),
                        ),
                        _ => alloy::primitives::U256::ZERO,
                    }
                };

                if use_block_in_place {
                    tokio::task::block_in_place(|| rt.block_on(fetch))
                } else if use_thread_bridge {
                    let rt = rt.clone();
                    let (tx, rx) = std::sync::mpsc::sync_channel(1);
                    std::thread::spawn(move || {
                        let _ = tx.send(rt.block_on(fetch));
                    });
                    match rx.recv() {
                        Ok(value) => value,
                        Err(_) => alloy::primitives::U256::ZERO,
                    }
                } else {
                    rt.block_on(fetch)
                }
            } else {
                alloy::primitives::U256::ZERO
            };

        out.push((*token, U256::from_limbs(attacker_bal_u256.into_limbs())));
    }
    out
}

pub fn hydrate_target_context(
    rpc_url: &str,
    chain_id: u64,
    target_address: Address,
    bytecode: &revm::primitives::Bytes,
    contracts_db: Option<&ContractsDb>,
) -> TargetContext {
    let attacker = ATTACKER;
    let preloaded_state = deep_scan_preloader_state_cache()
        .get(&target_address)
        .map(|entry| entry.value().clone());
    let preloaded_hit = preloaded_state.is_some();
    let mut effective_bytecode = bytecode.clone();
    if let Some(preloaded) = preloaded_state.as_ref() {
        if !preloaded.bytecode.is_empty() {
            effective_bytecode = preloaded.bytecode.clone();
        }
    }

    let mut preloaded_account_info: Option<AccountInfo> = None;
    let (fork_db, storage_slots, storage_scan_succeeded, remote_basic_balance) = if let Some(
        preloaded,
    ) =
        preloaded_state
    {
        preloaded_account_info = Some(preloaded.account_info.clone());
        (
            None,
            preloaded.storage_slots.clone(),
            preloaded.storage_scan_succeeded,
            preloaded.remote_balance,
        )
    } else {
        match ForkDB::new(rpc_url) {
            Ok(db) => {
                let (slots, scan_ok) = match db.scan_storage(target_address, STORAGE_SCAN_LIMIT) {
                    Ok(slots) => (slots, true),
                    Err(e) => {
                        let count = STORAGE_SCAN_WARN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        if count == 1 {
                            println!(
                                    "[Scan] Warning: Storage scan failed: {}. Continuing with empty storage snapshot (scan_failed=true).",
                                    e
                                );
                            println!(
                                "[Scan] Warning: Repeated storage scan errors will be suppressed."
                            );
                        } else if count.is_multiple_of(100) {
                            println!(
                                "[Scan] Warning: Suppressed {} repeated storage scan warnings.",
                                count - 1
                            );
                        }
                        (Vec::new(), false)
                    }
                };

                let remote_balance = match db.basic_ref(target_address) {
                    Ok(Some(info)) => Some(info.balance),
                    Ok(None) => Some(U256::ZERO),
                    Err(_) => None,
                };

                (Some(db), slots, scan_ok, remote_balance)
            }
            Err(err) => {
                eprintln!(
                        "[WARN] Target hydration ForkDB init failed; continuing with empty storage snapshot: {err}"
                    );
                (None, Vec::new(), false, None)
            }
        }
    };

    let zero_state = compute_zero_state_flag(
        &effective_bytecode,
        remote_basic_balance,
        &storage_slots,
        storage_scan_succeeded,
    );

    let mut account_info =
        preloaded_account_info.unwrap_or_else(|| default_account_info(&effective_bytecode));
    if let Some(db) = fork_db.as_ref() {
        match db.basic_ref(target_address) {
            Ok(Some(mut remote_info)) => {
                let code_obj = Bytecode::new_raw(effective_bytecode.clone());
                remote_info.code_hash = code_obj.hash_slow();
                remote_info.code = Some(code_obj);
                if !zero_state {
                    if remote_info.balance < default_contract_balance() {
                        remote_info.balance = default_contract_balance();
                    }
                    if remote_info.nonce == 0 {
                        remote_info.nonce = 1;
                    }
                }
                account_info = remote_info;
            }
            Ok(None) if zero_state => {
                let code_obj = Bytecode::new_raw(effective_bytecode.clone());
                account_info = AccountInfo::new(U256::ZERO, 0, code_obj.hash_slow(), code_obj);
            }
            _ => {}
        }
    }

    // Recursive proxy resolver: if this target is a proxy, prewarm implementation/facet code and
    // scan selectors from the underlying logic bytecode (EIP-1967 / EIP-897 / Diamond).
    let mut proxy_dependency_contexts: Vec<DependencyContext> = Vec::new();
    let mut proxy_bytecode_slice: Option<BytecodeSlice> = None;
    let mut token_scan_override: Option<Bytes> = None;

    if proxy_resolution_enabled() && bytecode_looks_like_proxy(&effective_bytecode) {
        if let Some(db) = fork_db.as_ref() {
            let mut seen: HashSet<Address> = HashSet::new();
            seen.insert(target_address);
            let mut queue: Vec<(Address, usize)> = vec![(target_address, 0)];
            let mut scan_slices: Vec<BytecodeSlice> = Vec::new();

            while let Some((addr, depth)) = queue.pop() {
                if depth >= proxy_resolution_max_depth() {
                    continue;
                }

                // EIP-1967 implementation slot.
                let impl_slot = U256::from_be_bytes(crate::utils::constants::EIP1967_IMPL_SLOT);
                if let Ok(word) = db.storage_ref(addr, impl_slot) {
                    if let Some(impl_addr) = crate::fork_db::decode_low160_address_from_word(word) {
                        if impl_addr != addr && seen.insert(impl_addr) {
                            queue.push((impl_addr, depth + 1));
                        }
                        if let Ok(Some(info)) = db.basic_ref(impl_addr) {
                            if let Some(code) = info.code.as_ref() {
                                let bytes = code.bytes();
                                if !bytes.is_empty() && !bytecode_looks_like_proxy(&bytes) {
                                    if token_scan_override.is_none() {
                                        token_scan_override = Some(bytes.clone());
                                    }
                                    scan_slices.push(hydrate_bytecode_slice(contracts_db, &bytes));
                                }
                            }
                            proxy_dependency_contexts.push(DependencyContext {
                                address: impl_addr,
                                account_info: info,
                                storage_slots: Vec::new(),
                            });
                        }
                        if let Some(db) = contracts_db {
                            if let Err(err) = db.replace_proxy_resolutions(
                                crate::symbolic::z3_ext::revm_to_alloy(addr),
                                chain_id,
                                "eip1967_implementation",
                                &[crate::symbolic::z3_ext::revm_to_alloy(impl_addr)],
                            ) {
                                eprintln!(
                                    "[WARN] Proxy resolution DB write failed for {addr:#x}: {err}"
                                );
                            }
                        }
                    }
                }

                // EIP-1967 beacon slot -> beacon.implementation().
                let beacon_slot = U256::from_be_bytes(crate::fork_db::EIP1967_BEACON_SLOT);
                if let Ok(beacon_word) = db.storage_ref(addr, beacon_slot) {
                    if let Some(beacon_addr) =
                        crate::fork_db::decode_low160_address_from_word(beacon_word)
                    {
                        let sel = selector("implementation()");
                        if let Ok(ret) = db.eth_call(beacon_addr, &sel) {
                            if let Some(impl_addr) = decode_address_from_abi_word(&ret) {
                                if impl_addr != addr && seen.insert(impl_addr) {
                                    queue.push((impl_addr, depth + 1));
                                }
                                if let Ok(Some(info)) = db.basic_ref(impl_addr) {
                                    if let Some(code) = info.code.as_ref() {
                                        let bytes = code.bytes();
                                        if !bytes.is_empty() && !bytecode_looks_like_proxy(&bytes) {
                                            if token_scan_override.is_none() {
                                                token_scan_override = Some(bytes.clone());
                                            }
                                            scan_slices
                                                .push(hydrate_bytecode_slice(contracts_db, &bytes));
                                        }
                                    }
                                    proxy_dependency_contexts.push(DependencyContext {
                                        address: impl_addr,
                                        account_info: info,
                                        storage_slots: Vec::new(),
                                    });
                                }
                                if let Some(db) = contracts_db {
                                    if let Err(err) = db.replace_proxy_resolutions(
                                        crate::symbolic::z3_ext::revm_to_alloy(addr),
                                        chain_id,
                                        "eip1967_beacon_implementation",
                                        &[crate::symbolic::z3_ext::revm_to_alloy(impl_addr)],
                                    ) {
                                        eprintln!(
                                            "[WARN] Proxy resolution DB write failed for {addr:#x}: {err}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                // EIP-897: proxy implementation() view.
                let sel = selector("implementation()");
                if let Ok(ret) = db.eth_call(addr, &sel) {
                    if let Some(impl_addr) = decode_address_from_abi_word(&ret) {
                        if impl_addr != addr && seen.insert(impl_addr) {
                            queue.push((impl_addr, depth + 1));
                        }
                        if let Ok(Some(info)) = db.basic_ref(impl_addr) {
                            if let Some(code) = info.code.as_ref() {
                                let bytes = code.bytes();
                                if !bytes.is_empty() && !bytecode_looks_like_proxy(&bytes) {
                                    if token_scan_override.is_none() {
                                        token_scan_override = Some(bytes.clone());
                                    }
                                    scan_slices.push(hydrate_bytecode_slice(contracts_db, &bytes));
                                }
                            }
                            proxy_dependency_contexts.push(DependencyContext {
                                address: impl_addr,
                                account_info: info,
                                storage_slots: Vec::new(),
                            });
                        }
                        if let Some(db) = contracts_db {
                            if let Err(err) = db.replace_proxy_resolutions(
                                crate::symbolic::z3_ext::revm_to_alloy(addr),
                                chain_id,
                                "eip897_implementation",
                                &[crate::symbolic::z3_ext::revm_to_alloy(impl_addr)],
                            ) {
                                eprintln!(
                                    "[WARN] Proxy resolution DB write failed for {addr:#x}: {err}"
                                );
                            }
                        }
                    }
                }

                // Diamond loupe: facetAddresses().
                let facets_sel = selector("facetAddresses()");
                if let Ok(ret) = db.eth_call(addr, &facets_sel) {
                    let facets = crate::fork_db::decode_abi_address_array(
                        &ret,
                        proxy_resolution_diamond_max_facets(),
                    );
                    if !facets.is_empty() {
                        let mut facets_for_db: Vec<alloy::primitives::Address> = Vec::new();
                        for facet in facets {
                            if !seen.insert(facet) {
                                continue;
                            }
                            facets_for_db.push(crate::symbolic::z3_ext::revm_to_alloy(facet));
                            if let Ok(Some(info)) = db.basic_ref(facet) {
                                if let Some(code) = info.code.as_ref() {
                                    let bytes = code.bytes();
                                    if !bytes.is_empty() && !bytecode_looks_like_proxy(&bytes) {
                                        if token_scan_override.is_none() {
                                            token_scan_override = Some(bytes.clone());
                                        }
                                        scan_slices
                                            .push(hydrate_bytecode_slice(contracts_db, &bytes));
                                    }
                                }
                                proxy_dependency_contexts.push(DependencyContext {
                                    address: facet,
                                    account_info: info,
                                    storage_slots: Vec::new(),
                                });
                            }
                        }
                        if let Some(db) = contracts_db {
                            if let Err(err) = db.replace_proxy_resolutions(
                                crate::symbolic::z3_ext::revm_to_alloy(addr),
                                chain_id,
                                "diamond_facet",
                                &facets_for_db,
                            ) {
                                eprintln!(
                                    "[WARN] Proxy resolution DB write failed for {addr:#x}: {err}"
                                );
                            }
                        }
                    }
                }
            }

            if !scan_slices.is_empty() {
                let mut merged = scan_slices.into_iter().fold(
                    BytecodeSlice {
                        selectors: Vec::new(),
                        nft_callback_selectors: Vec::new(),
                        dead_end_pcs: HashSet::new(),
                    },
                    merge_bytecode_slices,
                );
                // Keep selector lists bounded for 1800ms safety.
                if merged.selectors.len() > 512 {
                    merged.selectors.truncate(512);
                }
                if merged.nft_callback_selectors.len() > 256 {
                    merged.nft_callback_selectors.truncate(256);
                }
                proxy_bytecode_slice = Some(merged);
            }
        }
    }

    let token_scan_bytecode = token_scan_override.as_ref().unwrap_or(&effective_bytecode);
    let tokens = discover_candidate_tokens(chain_id, token_scan_bytecode, attacker, target_address);
    let attacker_token_balances = fetch_attacker_token_balances(
        if preloaded_hit { None } else { Some(rpc_url) },
        &tokens,
        attacker,
    );
    let bytecode_slice = proxy_bytecode_slice
        .unwrap_or_else(|| hydrate_bytecode_slice(contracts_db, &effective_bytecode));

    let mut dependencies = Vec::new();
    dependencies.extend(proxy_dependency_contexts);
    if local_context_expansion_enabled() {
        let excludes = [attacker, target_address];
        let max = local_context_dependency_max();
        let storage_limit = local_context_dependency_storage_scan_limit();
        for dep_addr in discover_immediate_dependencies(token_scan_bytecode, &excludes, max) {
            let Some(db) = fork_db.as_ref() else {
                break;
            };
            let Ok(Some(dep_info)) = db.basic_ref(dep_addr) else {
                continue;
            };
            let has_code = dep_info
                .code
                .as_ref()
                .is_some_and(|code| !code.bytes().is_empty());
            if !has_code {
                continue;
            }

            let dep_slots = if storage_limit > 0 {
                match db.scan_storage(dep_addr, storage_limit) {
                    Ok(slots) => slots,
                    Err(err) => {
                        let count =
                            DEPENDENCY_STORAGE_SCAN_WARN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        if count == 1 {
                            println!(
                                "[Scan] Warning: dependency storage scan failed for {:?}: {}. Skipping dependency context.",
                                dep_addr,
                                err
                            );
                            println!(
                                "[Scan] Warning: Repeated dependency storage scan errors will be suppressed."
                            );
                        } else if count.is_multiple_of(100) {
                            println!(
                                "[Scan] Warning: Suppressed {} repeated dependency storage scan warnings.",
                                count - 1
                            );
                        }
                        continue;
                    }
                }
            } else {
                Vec::new()
            };

            dependencies.push(DependencyContext {
                address: dep_addr,
                account_info: dep_info,
                storage_slots: dep_slots,
            });
            if dependencies.len() >= max {
                break;
            }
        }
    }

    TargetContext {
        target_address,
        zero_state,
        account_info,
        storage_slots,
        attacker_token_balances,
        selectors: bytecode_slice.selectors,
        nft_callback_selectors: bytecode_slice.nft_callback_selectors,
        dead_end_pcs: bytecode_slice.dead_end_pcs,
        dependencies,
    }
}

pub struct StandardScenario<'ctx> {
    pub machine: SymbolicMachine<'ctx>,
    pub db: CacheDB<ForkDB>,
    pub attacker: Address,
    pub contract_addr: Address,
    pub flash_loan_amount: BV<'ctx>,
    pub flash_loan_parts: Vec<FlashLoanPart<'ctx>>,
}

#[derive(Debug, Clone)]
pub struct FlashLoanPart<'ctx> {
    pub provider: Address,
    pub token: Address,
    pub amount: BV<'ctx>,
    pub fee_bps: u32,
}

fn modeled_flash_loan_provider_fees(chain_id: u64) -> Vec<(Address, u32)> {
    let mut providers = crate::protocols::flash_loan::get_default_providers(chain_id)
        .into_iter()
        .map(|(address, provider)| (address, provider.fee_bps()))
        .collect::<Vec<_>>();

    // Keep solver provider variable naming deterministic across runs.
    providers.sort_by(|(addr_a, fee_a), (addr_b, fee_b)| {
        fee_a
            .cmp(fee_b)
            .then_with(|| addr_a.as_slice().cmp(addr_b.as_slice()))
    });
    providers
}

impl<'ctx> StandardScenario<'ctx> {
    pub fn try_new(
        ctx: &'ctx Context,
        solver: &'ctx Solver<'ctx>,
        rpc_url: &str,
        bytecode: &revm::primitives::Bytes,
        loan_name: &str,
    ) -> anyhow::Result<Self> {
        let attacker = ATTACKER;
        let contract_addr = TARGET;

        // 1. Initial Symbolic Variables
        let flash_loan_amount = BV::new_const(ctx, loan_name, 256);
        let mut machine = SymbolicMachine::new(ctx, solver, Some(rpc_url.to_string()));
        let mut flash_loan_parts = Vec::new();

        let hydrated_target = current_target_context();
        if let Some(target_ctx) = hydrated_target.as_ref() {
            machine.dead_end_pcs = target_ctx.dead_end_pcs.clone();
        } else {
            // Pre-scan bytecode for dead-end PCs (revert sinks) when no hydrated context is available.
            machine.dead_end_pcs = crate::solver::heuristics::scan_dead_end_pcs(bytecode);
        }

        // Inject Flash Loan Balance for Attacker
        machine.inject_balance_override(attacker, flash_loan_amount.clone());

        // Coordinated flash-loans: split `flash_loan_amount` across known providers so the model
        // can represent sourcing capital from multiple pools in the same atomic transaction.
        if std::env::var("COORDINATED_FLASH_LOANS_ENABLED")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(true)
        {
            let mut parts_sum = crate::symbolic::utils::math::zero(ctx);
            let chain_id = match modeling_chain_id() {
                Ok(chain_id) => chain_id,
                Err(err) => {
                    let rpc_lc = rpc_url.to_ascii_lowercase();
                    let is_local_model =
                        rpc_lc.contains("localhost") || rpc_lc.contains("127.0.0.1");
                    if is_local_model {
                        crate::config::chains::ChainConfig::base().chain_id
                    } else {
                        return Err(err);
                    }
                }
            };
            let chain_weth = crate::config::chains::ChainConfig::get(chain_id).weth;

            for (idx, (provider, fee_bps)) in modeled_flash_loan_provider_fees(chain_id)
                .iter()
                .enumerate()
            {
                let part_name = format!("{loan_name}_part_{idx}");
                let amount = BV::new_const(ctx, part_name, 256);

                // Guard against modular-wrap artifacts: each part must be <= total loan.
                solver.assert(&amount.bvule(&flash_loan_amount));

                flash_loan_parts.push(FlashLoanPart {
                    provider: *provider,
                    token: Address::from_slice(chain_weth.as_slice()),
                    amount: amount.clone(),
                    fee_bps: *fee_bps,
                });
                parts_sum = parts_sum.bvadd(&amount);
            }

            // Require that the total loan equals the sum of its provider legs.
            solver.assert(&parts_sum._eq(&flash_loan_amount));
        }

        // Seed Oracle with Attacker Slots (Common Heuristic)
        machine.seed_oracle(attacker, Some(contract_addr));

        if let Some(target_ctx) = hydrated_target.as_ref() {
            if !target_ctx.storage_slots.is_empty() {
                machine.hydrate_storage(contract_addr, target_ctx.storage_slots.clone());
            }
        }

        // 2. Setup DB with ForkDB
        let fork_db = ForkDB::new(rpc_url)?;
        if hydrated_target.is_none() {
            let scanned_slots = scan_storage_with_warning(&fork_db, contract_addr);
            if !scanned_slots.is_empty() {
                machine.hydrate_storage(contract_addr, scanned_slots);
            }
        }
        let mut db = CacheDB::new(fork_db);
        let info = hydrated_target
            .as_ref()
            .map(|target_ctx| target_ctx.account_info.clone())
            .unwrap_or_else(|| default_account_info(bytecode));
        db.insert_account_info(contract_addr, info);
        if let Some(target_ctx) = hydrated_target.as_ref() {
            for dep in &target_ctx.dependencies {
                db.insert_account_info(dep.address, dep.account_info.clone());
                if !dep.storage_slots.is_empty() {
                    machine.hydrate_storage(dep.address, dep.storage_slots.clone());
                }
            }
        }

        Ok(Self {
            machine,
            db,
            attacker,
            contract_addr,
            flash_loan_amount,
            flash_loan_parts,
        })
    }

    pub fn init_tokens(
        &mut self,
        chain_id: u64,
        bytecode: &revm::primitives::Bytes,
    ) -> Vec<(Address, BV<'ctx>)> {
        let mut initial_token_vars = Vec::new();
        let token_balances = if let Some(target_ctx) = current_target_context() {
            target_ctx.attacker_token_balances.clone()
        } else {
            let tokens =
                discover_candidate_tokens(chain_id, bytecode, self.attacker, self.contract_addr);
            fetch_attacker_token_balances(self.machine.fork_url.as_deref(), &tokens, self.attacker)
        };

        let attacker = self.attacker;
        for (token, attacker_bal_u256) in token_balances {
            let initial_bal =
                crate::symbolic::z3_ext::bv_from_u256(self.machine.context, attacker_bal_u256);

            self.machine
                .token_balances
                .insert((token, attacker), initial_bal.clone());
            initial_token_vars.push((token, initial_bal));
        }

        initial_token_vars
    }

    pub fn constrain_loan(&self, solver: &Solver<'ctx>, limit_str: &str) {
        // Bound the flash-loan variable to a realistic maximum.
        if let Some(max_loan) = BV::from_str(self.machine.context, 256, limit_str) {
            solver.assert(&self.flash_loan_amount.bvult(&max_loan));
        } else {
            eprintln!(
                "[WARN] Invalid flash-loan upper bound `{}`; skipping loan-size constraint.",
                limit_str
            );
        }
    }

    /// Lightweight CacheDB setup for concrete-only passes (initial tracing).
    /// No symbolic machine, no storage scan, no oracle seeding.
    pub fn lightweight_db(
        rpc_url: &str,
        bytecode: &revm::primitives::Bytes,
    ) -> anyhow::Result<CacheDB<ForkDB>> {
        let fork_db = ForkDB::new(rpc_url)?;
        let mut db = CacheDB::new(fork_db);
        if let Some(target_ctx) = current_target_context() {
            db.insert_account_info(TARGET, target_ctx.account_info.clone());
            for dep in &target_ctx.dependencies {
                db.insert_account_info(dep.address, dep.account_info.clone());
            }
        } else {
            let info = default_account_info(bytecode);
            db.insert_account_info(TARGET, info);
        }
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        current_target_context, decode_multicall_balance_results, default_contract_balance,
        enter_target_context, modeled_flash_loan_provider_fees, DependencyContext,
        Multicall3Result, StandardScenario, TargetContext, ATTACKER, TARGET,
    };
    use crate::symbolic::z3_ext::u256_from_bv;
    use alloy::sol_types::SolCall;
    use revm::primitives::{AccountInfo, Address, Bytecode, Bytes, U256};
    use revm::Database;
    use std::collections::HashSet;
    use std::sync::Arc;
    use z3::{Config, Context, Solver};

    fn context_with_balance(
        bytecode: &Bytes,
        balance: U256,
        nonce: u64,
        token_balances: Vec<(Address, U256)>,
    ) -> Arc<TargetContext> {
        let code_obj = Bytecode::new_raw(bytecode.clone());
        Arc::new(TargetContext {
            target_address: TARGET,
            zero_state: false,
            account_info: AccountInfo::new(balance, nonce, code_obj.hash_slow(), code_obj),
            storage_slots: vec![(U256::from(7u64), U256::from(9u64))],
            attacker_token_balances: token_balances,
            selectors: crate::solver::heuristics::scan_for_state_changing_selectors(bytecode),
            nft_callback_selectors: crate::solver::heuristics::scan_for_nft_callback_selectors(
                bytecode,
            ),
            dead_end_pcs: HashSet::new(),
            dependencies: Vec::new(),
        })
    }

    #[test]
    fn test_init_tokens_reuses_hydrated_target_context() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let bytecode = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00]);
        let token_a = Address::new([0x11; 20]);
        let token_b = Address::new([0x22; 20]);
        let hydrated = context_with_balance(
            &bytecode,
            U256::from(777u64),
            9,
            vec![(token_a, U256::from(123u64)), (token_b, U256::ZERO)],
        );

        let _scope = enter_target_context(Arc::clone(&hydrated));
        let mut scenario = StandardScenario::try_new(
            &ctx,
            &solver,
            "http://localhost:8545",
            &bytecode,
            "flash_loan_amount",
        )
        .expect("scenario init");
        let info = scenario
            .db
            .basic(TARGET)
            .expect("cache lookup must succeed")
            .expect("target account info must be inserted");
        assert_eq!(info.balance, U256::from(777u64));
        assert_eq!(info.nonce, 9);
        assert!(scenario.machine.storage.contains_key(&TARGET));

        let initial_tokens = scenario.init_tokens(8453, &bytecode);
        assert_eq!(initial_tokens.len(), 2);
        assert_eq!(initial_tokens[0].0, token_a);
        assert_eq!(u256_from_bv(&initial_tokens[0].1), Some(U256::from(123u64)));
        assert_eq!(initial_tokens[1].0, token_b);
        assert_eq!(u256_from_bv(&initial_tokens[1].1), Some(U256::ZERO));
        assert!(scenario
            .machine
            .token_balances
            .contains_key(&(token_a, ATTACKER)));
    }

    #[test]
    fn test_target_context_scope_restores_previous_context() {
        let bytecode = Bytes::from_static(&[0x60, 0x01]);
        assert!(current_target_context().is_none());

        let ctx_a = context_with_balance(
            &bytecode,
            default_contract_balance(),
            1,
            vec![(Address::new([0x33; 20]), U256::from(1u64))],
        );
        let ctx_b = context_with_balance(
            &bytecode,
            U256::from(9_999u64),
            2,
            vec![(Address::new([0x44; 20]), U256::from(2u64))],
        );

        let _scope_a = enter_target_context(Arc::clone(&ctx_a));
        assert_eq!(
            current_target_context()
                .expect("context a should be active")
                .account_info
                .balance,
            default_contract_balance()
        );

        {
            let _scope_b = enter_target_context(Arc::clone(&ctx_b));
            assert_eq!(
                current_target_context()
                    .expect("context b should be active")
                    .account_info
                    .balance,
                U256::from(9_999u64)
            );
        }

        assert_eq!(
            current_target_context()
                .expect("context a should be restored")
                .account_info
                .balance,
            default_contract_balance()
        );
    }

    #[test]
    fn test_decode_multicall_balance_results_uses_success_flags() {
        let token_a = Address::new([0x51; 20]);
        let token_b = Address::new([0x52; 20]);
        let multicall_returns = vec![
            Multicall3Result {
                success: true,
                returnData: U256::from(17u64).to_be_bytes::<32>().to_vec().into(),
            },
            Multicall3Result {
                success: false,
                returnData: U256::from(99u64).to_be_bytes::<32>().to_vec().into(),
            },
        ];
        let encoded = <super::aggregate3Call as SolCall>::abi_encode_returns(&(multicall_returns,));
        let decoded = decode_multicall_balance_results(&[token_a, token_b], &encoded)
            .expect("decode should succeed");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (token_a, U256::from(17u64)));
        assert_eq!(decoded[1], (token_b, U256::ZERO));
    }

    #[test]
    fn test_standard_scenario_inserts_dependency_accounts_from_context() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let bytecode = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00]);

        let dep = Address::new([0xCC; 20]);
        let dep_code_bytes = Bytes::from_static(&[0x60, 0x00, 0x00]);
        let dep_code_obj = Bytecode::new_raw(dep_code_bytes.clone());
        let dep_info = AccountInfo::new(
            U256::from(123u64),
            7,
            dep_code_obj.hash_slow(),
            dep_code_obj,
        );

        let mut hydrated = context_with_balance(&bytecode, U256::from(777u64), 9, Vec::new());
        let mut cloned = (*hydrated).clone();
        cloned.dependencies.push(DependencyContext {
            address: dep,
            account_info: dep_info.clone(),
            storage_slots: vec![(U256::from(1u64), U256::from(2u64))],
        });
        hydrated = Arc::new(cloned);

        let _scope = enter_target_context(Arc::clone(&hydrated));
        let mut scenario = StandardScenario::try_new(
            &ctx,
            &solver,
            "http://localhost:8545",
            &bytecode,
            "flash_loan_amount",
        )
        .expect("scenario init");
        let loaded = scenario
            .db
            .basic(dep)
            .expect("dependency cache lookup must succeed")
            .expect("dependency account info must be inserted");
        assert_eq!(loaded.balance, U256::from(123u64));
        assert_eq!(loaded.nonce, 7);

        let dep_arr = scenario.machine.get_storage(dep);
        let key = crate::symbolic::z3_ext::bv_from_u256(&ctx, U256::from(1u64));
        let got = dep_arr
            .select(&key)
            .as_bv()
            .expect("storage array must be BV-typed");
        assert_eq!(u256_from_bv(&got), Some(U256::from(2u64)));
    }

    #[test]
    fn test_modeled_flash_loan_provider_fees_mirrors_provider_registry() {
        let chain_id = crate::config::chains::ChainConfig::base().chain_id;
        let modeled = modeled_flash_loan_provider_fees(chain_id);
        let providers = crate::protocols::flash_loan::get_default_providers(chain_id);

        assert!(!modeled.is_empty());
        assert_eq!(
            modeled.len(),
            providers.len(),
            "modeled provider list must match runtime provider registry cardinality"
        );
        for (address, fee_bps) in modeled {
            let provider = providers
                .get(&address)
                .expect("modeled provider address must exist in runtime provider registry");
            assert_eq!(
                fee_bps,
                provider.fee_bps(),
                "modeled fee must match runtime provider fee for {address:#x}"
            );
        }
    }

    #[test]
    fn test_modeled_flash_loan_provider_fees_are_deterministically_ordered() {
        let chain_id = crate::config::chains::ChainConfig::base().chain_id;
        let modeled = modeled_flash_loan_provider_fees(chain_id);
        assert!(!modeled.is_empty());

        for pair in modeled.windows(2) {
            let (addr_a, fee_a) = pair[0];
            let (addr_b, fee_b) = pair[1];
            assert!(
                fee_a < fee_b
                    || (fee_a == fee_b && addr_a.as_slice().cmp(addr_b.as_slice()).is_le()),
                "provider list must be sorted by fee then address for deterministic symbolic vars"
            );
        }
    }
}
