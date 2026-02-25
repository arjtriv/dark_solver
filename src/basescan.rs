use alloy::primitives::{Address, Bytes as ABytes, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{Filter, TransactionInput, TransactionRequest};
use alloy::transports::http::Http;
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use crate::storage::contracts_db::ContractsDb;
use crate::target_queue::{TargetPriority, TargetQueueSender};

type HttpProvider = RootProvider<Http<reqwest::Client>>;

// ---------------------------------------------------------------------------
// Basescan API types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BasescanResponse<T> {
    status: String,
    #[allow(dead_code)]
    message: String,
    result: T,
}

// ---------------------------------------------------------------------------
// Known Base DeFi: factories, routers, vaults, lending cores
// ---------------------------------------------------------------------------

/// Contracts with length()/getter() style enumeration (Aerodrome, Moonwell).
struct IndexedFactory {
    name: &'static str,
    address: Address,
    length_selector: [u8; 4],
    getter_selector: [u8; 4],
    max_enumerate: usize,
}

fn indexed_factories() -> Vec<IndexedFactory> {
    vec![
        IndexedFactory {
            name: "Aerodrome",
            address: addr("0x420DD381b31aEf6683db6B902084cB0FFECe40Da"),
            length_selector: [0xef, 0xb7, 0x60, 0x1d], // allPoolsLength()
            getter_selector: [0x41, 0xd1, 0xde, 0x97], // allPools(uint256)
            max_enumerate: 300,
        },
        IndexedFactory {
            name: "Moonwell",
            // Moonwell Comptroller — allMarkets() returns Address[], but we use
            // getAllMarkets() which is a view returning the full array.
            // Selector: getAllMarkets() = 0xb0772d0b
            // Falls back to indexed style: allMarketsSize + allMarkets(uint256)
            // Actually uses: allMarkets(uint256) = 0x52d84d1e, length via allMarketsSize not available.
            // We'll use a different approach: call allMarkets() which returns address[]
            address: addr("0xfBb21d0380beE3312B33c4353c8936a0F13EF26C"),
            length_selector: [0x00; 4], // not used, we call getAllMarkets() directly
            getter_selector: [0x00; 4],
            max_enumerate: 0, // signals: use array-return approach instead
        },
    ]
}

/// Contracts where we call a single function that returns address[].
struct ArrayFactory {
    name: &'static str,
    address: Address,
    /// Selector for function that returns address[]
    selector: [u8; 4],
}

fn array_factories() -> Vec<ArrayFactory> {
    vec![ArrayFactory {
        name: "Moonwell",
        address: addr("0xfBb21d0380beE3312B33c4353c8936a0F13EF26C"),
        selector: [0xb0, 0x77, 0x2d, 0x0b], // getAllMarkets()
    }]
}

/// Event-log based pool discovery (UniV3 PoolCreated, etc.).
struct EventFactory {
    name: &'static str,
    address: Address,
    /// topic0 of the creation event
    topic0: FixedBytes<32>,
    /// How far back (in blocks) to scan for events
    lookback_blocks: u64,
}

fn event_factories() -> Vec<EventFactory> {
    vec![EventFactory {
        name: "UniswapV3",
        address: addr("0x33128a8fC17869897dcE68Ed026d694621f6FDfD"),
        // PoolCreated(address,address,uint24,int24,address)
        // keccak256 = 0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118
        topic0: FixedBytes::from_slice(&hex_decode(
            "783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118",
        )),
        lookback_blocks: 100_000, // ~2.3 days on Base (2s blocks)
    }]
}

/// Static high-value targets — contracts that definitely hold funds and have
/// non-trivial logic. Enqueued every cycle as Hot priority.
fn seed_contracts() -> Vec<(Address, &'static str)> {
    vec![
        (
            addr("0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43"),
            "Aerodrome V2 Router",
        ),
        (
            addr("0x420DD381b31aEf6683db6B902084cB0FFECe40Da"),
            "Aerodrome V2 Factory",
        ),
        (
            addr("0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb"),
            "Morpho Blue",
        ),
        (
            addr("0xfBb21d0380beE3312B33c4353c8936a0F13EF26C"),
            "Moonwell Comptroller",
        ),
        (
            addr("0x8F44Fd754285aa6A2b8B9B97739B79746e0475a7"),
            "Seamless Protocol Pool",
        ),
        (
            addr("0xBA12222222228d8Ba445958a75a0704d566BF2C8"),
            "Balancer Vault",
        ),
        (
            addr("0x33128a8fC17869897dcE68Ed026d694621f6FDfD"),
            "UniswapV3 Factory",
        ),
        // SushiSwap on Base
        (
            addr("0x6BDED42c6DA8FBf0d2bA55B2fa120C5e0c8D7891"),
            "SushiSwap V3 Factory",
        ),
        // BaseSwap
        (
            addr("0xFDa619b6d20975be80A10332cD39b9a4b0FAa8BB"),
            "BaseSwap Factory",
        ),
        // Aave V3 Pool on Base
        (
            addr("0xA238Dd80C259a72e81d7e4664a9801593F98d1c5"),
            "Aave V3 Pool",
        ),
        // Compound V3 (Comet) USDC on Base
        (
            addr("0xb125E6687d4313864e53df431d5425969c15Eb2F"),
            "Compound V3 cUSDCv3",
        ),
        // Extra Finance
        (
            addr("0xBB505c54D71E9e599cB8435b4F0cEEc05fC71cbD"),
            "Extra Finance Lending",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn addr(s: &str) -> Address {
    Address::from_str(s).unwrap()
}

fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

const BASESCAN_API_BASE: &str = "https://api.basescan.org/api";
const MAX_RETRIES: u32 = 3;

async fn basescan_get<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(1000 * 2u64.pow(attempt - 1))).await;
        }
        match client
            .get(url)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => match resp.json::<T>().await {
                Ok(parsed) => return Ok(parsed),
                Err(e) => last_err = Some(e.into()),
            },
            Ok(resp) => last_err = Some(anyhow::anyhow!("HTTP {}", resp.status())),
            Err(e) => last_err = Some(e.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("basescan_get: exhausted retries")))
}

// ---------------------------------------------------------------------------
// Basescan API: contract creation discovery via token transfer logs
// ---------------------------------------------------------------------------

/// Find contracts that received ERC20 transfers (topic0 = Transfer, to = contract).
/// Uses Basescan getLogs endpoint to find contracts accumulating tokens.
async fn discover_token_receiving_contracts(
    client: &reqwest::Client,
    api_key: &str,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Address>> {
    // ERC20 Transfer event: Transfer(address,address,uint256)
    // topic0 = 0xddf252ad...
    let topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

    // We can't filter by "to is a contract" via the API alone, but we can
    // get recent transfer events and collect unique `to` addresses, then
    // filter by code size via RPC later.
    let url = format!(
        "{}?module=logs&action=getLogs&fromBlock={}&toBlock={}&topic0={}&page=1&offset=1000&apikey={}",
        BASESCAN_API_BASE, from_block, to_block, topic0, api_key
    );

    #[derive(Deserialize)]
    struct LogEntry {
        #[allow(dead_code)]
        address: Option<String>,
        topics: Option<Vec<String>>,
    }

    let resp: BasescanResponse<Vec<LogEntry>> = basescan_get(client, &url).await?;
    if resp.status != "1" {
        return Ok(Vec::new());
    }

    let mut recipients = HashSet::new();
    for log in &resp.result {
        // topic[2] is the `to` address in Transfer events (indexed)
        if let Some(topics) = &log.topics {
            if topics.len() >= 3 {
                let to_topic = topics[2].trim();
                // topic is 32-byte hex, address is last 20 bytes
                if to_topic.len() >= 66 {
                    let addr_hex = format!("0x{}", &to_topic[26..]);
                    if let Ok(a) = Address::from_str(&addr_hex) {
                        if !a.is_zero() {
                            recipients.insert(a);
                        }
                    }
                }
            }
        }
    }

    Ok(recipients.into_iter().collect())
}

// ---------------------------------------------------------------------------
// RPC-based enumeration
// ---------------------------------------------------------------------------

/// Enumerate pools from an indexed factory (allPoolsLength + allPools(i)).
async fn enumerate_indexed_factory(
    provider: &HttpProvider,
    factory: &IndexedFactory,
) -> Result<Vec<Address>> {
    if factory.max_enumerate == 0 {
        return Ok(Vec::new());
    }

    let length_calldata = ABytes::from(factory.length_selector.to_vec());
    let length_tx = TransactionRequest::default()
        .to(factory.address)
        .input(TransactionInput::new(length_calldata));

    let length_result = provider.call(&length_tx).await?;
    if length_result.len() < 32 {
        return Ok(Vec::new());
    }
    let total: usize = U256::from_be_slice(&length_result[..32])
        .try_into()
        .unwrap_or(0);
    let count = total.min(factory.max_enumerate);

    eprintln!(
        "[BASESCAN] {} factory: {} total, enumerating last {}",
        factory.name, total, count
    );

    let mut pools = Vec::with_capacity(count);
    for i in 0..count {
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
                let a = Address::from_slice(&result[12..32]);
                if !a.is_zero() {
                    pools.push(a);
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    "[BASESCAN] {} enumerate error at {}: {}",
                    factory.name,
                    idx,
                    e
                );
                break;
            }
        }

        if i % 25 == 24 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    Ok(pools)
}

/// Call a function that returns address[] and decode the result.
async fn call_array_factory(
    provider: &HttpProvider,
    factory: &ArrayFactory,
) -> Result<Vec<Address>> {
    let calldata = ABytes::from(factory.selector.to_vec());
    let tx = TransactionRequest::default()
        .to(factory.address)
        .input(TransactionInput::new(calldata));

    let result = provider.call(&tx).await?;
    // ABI: offset (32 bytes) + length (32 bytes) + length * 32-byte address words
    if result.len() < 64 {
        return Ok(Vec::new());
    }
    let len: usize = U256::from_be_slice(&result[32..64]).try_into().unwrap_or(0);
    let mut addrs = Vec::with_capacity(len);
    for i in 0..len {
        let start = 64 + i * 32;
        if start + 32 > result.len() {
            break;
        }
        let a = Address::from_slice(&result[start + 12..start + 32]);
        if !a.is_zero() {
            addrs.push(a);
        }
    }

    eprintln!(
        "[BASESCAN] {} getAllMarkets: {} markets",
        factory.name,
        addrs.len()
    );
    Ok(addrs)
}

/// Discover pools via PoolCreated event logs from factory contracts.
async fn discover_event_factory_pools(
    provider: &HttpProvider,
    factory: &EventFactory,
) -> Result<Vec<Address>> {
    let head = provider.get_block_number().await.unwrap_or(0);
    if head == 0 {
        return Ok(Vec::new());
    }
    let from_block = head.saturating_sub(factory.lookback_blocks);

    let filter = Filter::new()
        .address(factory.address)
        .event_signature(factory.topic0)
        .from_block(from_block)
        .to_block(head);

    let logs = provider.get_logs(&filter).await?;
    let mut pools = Vec::new();

    for log in &logs {
        // For UniV3 PoolCreated, the pool address is the last 20 bytes of the
        // 5th topic... but actually it's in the log data, not topics.
        // PoolCreated(token0, token1, fee, tickSpacing, pool)
        // topics: [sig, token0, token1, fee]
        // data: [tickSpacing (int24 padded), pool (address padded)]
        // pool is at data offset 32 (second 32-byte word)
        if log.data().data.len() >= 64 {
            let a = Address::from_slice(&log.data().data[44..64]);
            if !a.is_zero() {
                pools.push(a);
            }
        }
    }

    eprintln!(
        "[BASESCAN] {} event factory: {} pools from {} logs (blocks {}..{})",
        factory.name,
        pools.len(),
        logs.len(),
        from_block,
        head
    );
    Ok(pools)
}

/// Filter addresses to only those with deployed code (i.e., actual contracts, not EOAs).
async fn filter_contracts_only(
    provider: &HttpProvider,
    addresses: Vec<Address>,
    max_check: usize,
) -> Vec<Address> {
    let mut contracts = Vec::new();
    for (i, addr) in addresses.into_iter().take(max_check).enumerate() {
        match provider.get_code_at(addr).await {
            Ok(code) if code.len() > 2 => {
                contracts.push(addr);
            }
            _ => {}
        }
        if i % 30 == 29 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    contracts
}

// ---------------------------------------------------------------------------
// Single cycle
// ---------------------------------------------------------------------------

async fn run_one_cycle(
    client: &reqwest::Client,
    target_sender: &TargetQueueSender,
    contracts_db: &Option<ContractsDb>,
    api_key: &str,
    rpc_url: &str,
    enqueue_delay: Duration,
) -> Result<usize> {
    let mut seen = HashSet::new();
    let mut all: Vec<(Address, &str)> = Vec::new();

    // Helper closure — dedup + collect
    let push = |addr: Address,
                seen: &mut HashSet<Address>,
                all: &mut Vec<(Address, &str)>,
                tag: &'static str| {
        if seen.insert(addr) {
            all.push((addr, tag));
        }
    };

    // 1. Seed contracts (always enqueued, known DeFi with non-trivial bytecode)
    for (a, name) in seed_contracts() {
        if seen.insert(a) {
            all.push((a, name));
        }
    }
    eprintln!("[BASESCAN] {} seed contracts", all.len());

    // 2. RPC-based factory enumeration
    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);

    // 2a. Indexed factories (Aerodrome)
    for factory in indexed_factories() {
        if factory.max_enumerate == 0 {
            continue;
        }
        match enumerate_indexed_factory(&provider, &factory).await {
            Ok(pools) => {
                let before = all.len();
                for a in pools {
                    push(a, &mut seen, &mut all, "factory-pool");
                }
                eprintln!(
                    "[BASESCAN] {} indexed factory: {} new pools",
                    factory.name,
                    all.len() - before
                );
            }
            Err(e) => eprintln!(
                "[BASESCAN] {} indexed factory failed: {:?}",
                factory.name, e
            ),
        }
    }

    // 2b. Array-return factories (Moonwell getAllMarkets)
    for factory in array_factories() {
        match call_array_factory(&provider, &factory).await {
            Ok(markets) => {
                let before = all.len();
                for a in markets {
                    push(a, &mut seen, &mut all, "lending-market");
                }
                eprintln!(
                    "[BASESCAN] {} array factory: {} new markets",
                    factory.name,
                    all.len() - before
                );
            }
            Err(e) => eprintln!("[BASESCAN] {} array factory failed: {:?}", factory.name, e),
        }
    }

    // 2c. Event-log factories (UniV3 PoolCreated)
    for factory in event_factories() {
        match discover_event_factory_pools(&provider, &factory).await {
            Ok(pools) => {
                let before = all.len();
                for a in pools {
                    push(a, &mut seen, &mut all, "event-pool");
                }
                eprintln!(
                    "[BASESCAN] {} event factory: {} new pools",
                    factory.name,
                    all.len() - before
                );
            }
            Err(e) => eprintln!("[BASESCAN] {} event factory failed: {:?}", factory.name, e),
        }
    }

    // 3. Basescan API: discover contracts receiving ERC20 tokens (if API key set)
    if !api_key.is_empty() {
        let head = provider.get_block_number().await.unwrap_or(0);
        if head > 5000 {
            match discover_token_receiving_contracts(
                client,
                api_key,
                head.saturating_sub(5000),
                head,
            )
            .await
            {
                Ok(recipients) => {
                    // Filter to actual contracts (not EOAs)
                    let contracts = filter_contracts_only(&provider, recipients, 200).await;
                    let before = all.len();
                    for a in contracts {
                        push(a, &mut seen, &mut all, "token-receiver");
                    }
                    eprintln!(
                        "[BASESCAN] Token-receiving contracts: {} new",
                        all.len() - before
                    );
                }
                Err(e) => eprintln!("[BASESCAN] Token receiver discovery failed: {:?}", e),
            }
            // Rate limit
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    eprintln!("[BASESCAN] Total unique targets: {}", all.len());

    // 4. Enqueue
    let mut enqueued = 0usize;
    for (addr, tag) in &all {
        if let Some(db) = contracts_db {
            let _ = db.mark_queued(*addr);
        }
        if target_sender.enqueue(*addr, TargetPriority::Hot).await {
            enqueued += 1;
            if enqueued <= 40 {
                eprintln!("[BASESCAN]   #{}: {:?} ({})", enqueued, addr, tag);
            }
        }
        tokio::time::sleep(enqueue_delay).await;
    }

    Ok(enqueued)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn start_basescan_feeder(
    target_sender: TargetQueueSender,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    contracts_db: Option<ContractsDb>,
) -> Result<()> {
    let enabled = std::env::var("BASESCAN_ENABLED")
        .unwrap_or_else(|_| "false".into())
        .eq_ignore_ascii_case("true");

    if !enabled {
        eprintln!("[BASESCAN] Disabled (BASESCAN_ENABLED != true). Exiting feeder.");
        return Ok(());
    }

    let api_key = std::env::var("BASESCAN_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        eprintln!("[BASESCAN] BASESCAN_API_KEY not set — API discovery disabled, RPC enumeration still active.");
    }

    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "https://base-rpc.publicnode.com".into());

    let rescan_secs: u64 = std::env::var("BASESCAN_RESCAN_INTERVAL_SECS")
        .unwrap_or_else(|_| "1800".into())
        .parse()
        .unwrap_or(1800);

    let enqueue_delay_ms: u64 = std::env::var("BASESCAN_ENQUEUE_DELAY_MS")
        .unwrap_or_else(|_| "25".into())
        .parse()
        .unwrap_or(25);

    let enqueue_delay = Duration::from_millis(enqueue_delay_ms);
    let rescan_interval = Duration::from_secs(rescan_secs);

    eprintln!(
        "[BASESCAN] Starting feeder: api_key={}, rescan={}s",
        if api_key.is_empty() { "NONE" } else { "SET" },
        rescan_secs
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    loop {
        match run_one_cycle(
            &client,
            &target_sender,
            &contracts_db,
            &api_key,
            &rpc_url,
            enqueue_delay,
        )
        .await
        {
            Ok(count) => eprintln!("[BASESCAN] Cycle complete: {} targets enqueued.", count),
            Err(e) => eprintln!("[BASESCAN] Cycle failed: {:?}. Retrying next cycle.", e),
        }

        tokio::select! {
            _ = tokio::time::sleep(rescan_interval) => {}
            _ = shutdown_rx.recv() => {
                eprintln!("[BASESCAN] Shutdown received. Exiting.");
                return Ok(());
            }
        }
    }
}
