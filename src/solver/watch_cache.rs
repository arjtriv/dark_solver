use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::rpc::types::Log;
use dashmap::DashMap;
use std::sync::OnceLock;

const UNIV2_SYNC_EVENT: &str = "Sync(uint112,uint112)";
const UNIV3_SWAP_EVENT: &str = "Swap(address,address,int256,int256,uint160,uint128,int24)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniV2State {
    pub reserve0: U256,
    pub reserve1: U256,
    pub block_timestamp: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniV3State {
    pub sqrt_price_x96: U256,
    pub liquidity: u128,
    pub tick: i32,
}

fn univ2_cache() -> &'static DashMap<Address, UniV2State> {
    static CACHE: OnceLock<DashMap<Address, UniV2State>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn univ3_cache() -> &'static DashMap<Address, UniV3State> {
    static CACHE: OnceLock<DashMap<Address, UniV3State>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn univ2_sync_topic() -> B256 {
    keccak256(UNIV2_SYNC_EVENT)
}

fn univ3_swap_topic() -> B256 {
    keccak256(UNIV3_SWAP_EVENT)
}

fn decode_u256_word(data: &[u8], offset: usize) -> Option<U256> {
    let word = data.get(offset..offset.saturating_add(32))?;
    if word.len() != 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(word);
    Some(U256::from_be_bytes(buf))
}

fn decode_u128_word(data: &[u8], offset: usize) -> Option<u128> {
    let word = data.get(offset..offset.saturating_add(32))?;
    if word.len() != 32 {
        return None;
    }
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&word[16..32]);
    Some(u128::from_be_bytes(tail))
}

fn decode_i24_word(data: &[u8], offset: usize) -> Option<i32> {
    let word = data.get(offset..offset.saturating_add(32))?;
    if word.len() != 32 {
        return None;
    }
    let raw = ((word[29] as i32) << 16) | ((word[30] as i32) << 8) | (word[31] as i32);
    Some(if (raw & 0x80_0000) != 0 {
        raw - 0x1_000000
    } else {
        raw
    })
}

fn block_timestamp_from_log(log: &Log) -> u32 {
    log.block_timestamp
        .or(log.block_number)
        .map(|v| v.min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

pub fn watched_event_topics() -> Vec<B256> {
    vec![univ2_sync_topic(), univ3_swap_topic()]
}

pub fn ingest_amm_log(log: &Log) -> anyhow::Result<()> {
    let Some(topic0) = log.topic0().copied() else {
        return Ok(());
    };
    let payload = log.data().data.as_ref();
    let address = log.address();

    if topic0 == univ2_sync_topic() {
        let Some(reserve0) = decode_u256_word(payload, 0) else {
            anyhow::bail!("malformed UniV2 Sync log payload: reserve0 missing");
        };
        let Some(reserve1) = decode_u256_word(payload, 32) else {
            anyhow::bail!("malformed UniV2 Sync log payload: reserve1 missing");
        };
        let state = UniV2State {
            reserve0,
            reserve1,
            block_timestamp: block_timestamp_from_log(log),
        };
        univ2_cache().insert(address, state);
        return Ok(());
    }

    if topic0 == univ3_swap_topic() {
        let Some(sqrt_price_x96) = decode_u256_word(payload, 64) else {
            anyhow::bail!("malformed UniV3 Swap log payload: sqrtPriceX96 missing");
        };
        let Some(liquidity) = decode_u128_word(payload, 96) else {
            anyhow::bail!("malformed UniV3 Swap log payload: liquidity missing");
        };
        let Some(tick) = decode_i24_word(payload, 128) else {
            anyhow::bail!("malformed UniV3 Swap log payload: tick missing");
        };
        let state = UniV3State {
            sqrt_price_x96,
            liquidity,
            tick,
        };
        univ3_cache().insert(address, state);
    }

    Ok(())
}

pub fn get_univ2_state(address: Address) -> Option<UniV2State> {
    univ2_cache().get(&address).map(|entry| *entry)
}

pub fn get_univ3_state(address: Address) -> Option<UniV3State> {
    univ3_cache().get(&address).map(|entry| *entry)
}

pub fn clear() {
    univ2_cache().clear();
    univ3_cache().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, Log as PrimitiveLog, LogData};

    fn make_rpc_log(address: Address, topics: Vec<B256>, data: Vec<u8>) -> Log {
        Log {
            inner: PrimitiveLog {
                address,
                data: LogData::new_unchecked(topics, Bytes::from(data)),
            },
            block_hash: None,
            block_number: Some(123),
            block_timestamp: Some(456),
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        }
    }

    fn word_u256(value: U256) -> [u8; 32] {
        value.to_be_bytes::<32>()
    }

    #[test]
    fn test_watched_event_topics_contains_expected_signatures() {
        let topics = watched_event_topics();
        assert!(topics.contains(&keccak256(UNIV2_SYNC_EVENT)));
        assert!(topics.contains(&keccak256(UNIV3_SWAP_EVENT)));
    }

    #[test]
    fn test_ingest_univ2_sync_updates_cache() {
        clear();
        let pair = Address::from([0x11; 20]);
        let mut data = Vec::new();
        data.extend_from_slice(&word_u256(U256::from(111u64)));
        data.extend_from_slice(&word_u256(U256::from(222u64)));
        let log = make_rpc_log(pair, vec![univ2_sync_topic()], data);

        ingest_amm_log(&log).expect("sync ingest");
        let state = get_univ2_state(pair).expect("v2 cached");
        assert_eq!(state.reserve0, U256::from(111u64));
        assert_eq!(state.reserve1, U256::from(222u64));
        assert_eq!(state.block_timestamp, 456);
    }

    #[test]
    fn test_ingest_univ3_swap_updates_cache() {
        clear();
        let pool = Address::from([0x22; 20]);
        let mut data = Vec::new();
        data.extend_from_slice(&word_u256(U256::from(1u64))); // amount0
        data.extend_from_slice(&word_u256(U256::from(2u64))); // amount1
        data.extend_from_slice(&word_u256(U256::from(3u64))); // sqrtPriceX96
        data.extend_from_slice(&word_u256(U256::from(4u64))); // liquidity
        let mut tick_word = [0u8; 32];
        tick_word[29] = 0xFF;
        tick_word[30] = 0xFF;
        tick_word[31] = 0xFF; // -1 in int24
        data.extend_from_slice(&tick_word);
        let log = make_rpc_log(pool, vec![univ3_swap_topic()], data);

        ingest_amm_log(&log).expect("swap ingest");
        let state = get_univ3_state(pool).expect("v3 cached");
        assert_eq!(state.sqrt_price_x96, U256::from(3u64));
        assert_eq!(state.liquidity, 4u128);
        assert_eq!(state.tick, -1);
    }

    #[test]
    fn test_decode_i24_word_sign_extension() {
        let mut plus = [0u8; 32];
        plus[29] = 0x00;
        plus[30] = 0x01;
        plus[31] = 0x02;
        assert_eq!(decode_i24_word(&plus, 0), Some(258));

        let mut minus = [0u8; 32];
        minus[29] = 0xFF;
        minus[30] = 0xFF;
        minus[31] = 0x00;
        assert_eq!(decode_i24_word(&minus, 0), Some(-256));
    }
}
