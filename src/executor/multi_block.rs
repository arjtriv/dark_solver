//! Multi-Block Bundle Construction
//!
//! Enables multi-step exploits that span multiple blocks.
//! For example: manipulate price in block N, wait for oracle update,
//! exploit in block N+1.

use crate::executor::builders::BundlePayload;
use crate::solver::objectives::ExploitStep;
use alloy::primitives::{Address, Bytes as AlloyBytes};
use std::collections::BTreeMap;

/// A bundle step annotated with which block it should execute in.
#[derive(Debug, Clone, Copy)]
pub struct BlockStep<'a> {
    pub step: &'a ExploitStep,
    /// Offset from current block. 0 = current block, 1 = next block, etc.
    pub block_offset: u64,
}

/// Groups exploit steps by their block offset and manages cross-block state.
pub struct MultiBlockExecutor<'a> {
    steps: Vec<BlockStep<'a>>,
}

impl<'a> MultiBlockExecutor<'a> {
    /// Create from `ExploitStep`s with optional per-step block offsets.
    ///
    /// If `block_offsets` is `None`, all steps execute in the current block (offset 0).
    pub fn new(steps: &'a [ExploitStep], block_offsets: Option<&'a [u64]>) -> Self {
        let block_steps = match block_offsets {
            Some(offsets) => steps
                .iter()
                .zip(offsets.iter().copied())
                .map(|(step, offset)| BlockStep {
                    step,
                    block_offset: offset,
                })
                .collect(),
            None => steps
                .iter()
                .map(|step| BlockStep {
                    step,
                    block_offset: 0,
                })
                .collect(),
        };

        Self { steps: block_steps }
    }

    /// Group steps by their block offset, maintaining order within each group.
    pub fn grouped_steps(&self) -> BTreeMap<u64, Vec<&BlockStep<'a>>> {
        let mut groups: BTreeMap<u64, Vec<&BlockStep<'a>>> = BTreeMap::new();
        for step in &self.steps {
            groups.entry(step.block_offset).or_default().push(step);
        }
        groups
    }

    /// Returns the maximum block offset (how many blocks this exploit spans).
    pub fn max_block_span(&self) -> u64 {
        self.steps.iter().map(|s| s.block_offset).max().unwrap_or(0)
    }

    /// Returns true if this exploit requires multiple blocks.
    pub fn is_multi_block(&self) -> bool {
        self.max_block_span() > 0
    }

    /// Convert grouped steps into per-block bundle payloads.
    ///
    /// Each group becomes a separate `eth_sendBundle` submission targeting
    /// `current_block + block_offset`.
    ///
    /// `signed_txs_by_group` maps: block_offset → Vec<signed_tx_bytes>
    pub fn to_bundles(
        &self,
        current_block: u64,
        signed_txs_by_group: &BTreeMap<u64, Vec<AlloyBytes>>,
        max_timestamp: u64,
    ) -> Vec<(u64, BundlePayload)> {
        let mut bundles = Vec::new();

        for (offset, txs) in signed_txs_by_group {
            let target_block = current_block + offset;
            let txs_hex = txs
                .iter()
                .map(|tx| format!("0x{:x}", tx))
                .map(|encoded| {
                    if let Some(stripped) = encoded.strip_prefix("0x0x") {
                        format!("0x{}", stripped)
                    } else {
                        encoded
                    }
                })
                .collect::<Vec<_>>();
            let bundle = BundlePayload {
                txs: txs_hex,
                block_number: format!("0x{:x}", target_block),
                min_timestamp: 0,
                max_timestamp,
                reverting_tx_hashes: vec![],
            };
            bundles.push((target_block, bundle));
        }

        bundles
    }

    /// Get the steps for simulation, preserving their block grouping.
    /// Returns (block_offset, target_address, calldata) triples.
    pub fn simulation_steps(&self) -> Vec<(u64, Address, &[u8])> {
        self.steps
            .iter()
            .map(|bs| (bs.block_offset, bs.step.target, bs.step.call_data.as_ref()))
            .collect()
    }
}

/// Advance simulated block environment between block boundaries.
///
/// Call this between groups to simulate time passing:
/// - `block.number += 1`
/// - `block.timestamp += block_time`
///
/// # Arguments
/// - `env_block` - Mutable reference to the REVM block environment
/// - `block_time` - Seconds per block (2 for Base, 12 for Ethereum Mainnet)
pub fn advance_block_env(block_number: &mut u64, block_timestamp: &mut u64, block_time: u64) {
    *block_number += 1;
    *block_timestamp += block_time;
}

/// Determine block time from chain ID.
pub fn block_time_for_chain(chain_id: u64) -> u64 {
    match chain_id {
        1 => 12,    // Ethereum Mainnet
        8453 => 2,  // Base
        10 => 2,    // Optimism
        42161 => 1, // Arbitrum (variable, ~0.25s, use 1s for safety)
        _ => 12,    // Default to Mainnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes};

    fn dummy_step(target: Address) -> ExploitStep {
        ExploitStep {
            target,
            call_data: Bytes::from_static(&[0xde, 0xad]),
            execute_if: None,
        }
    }

    #[test]
    fn test_single_block_grouping() {
        let steps = vec![dummy_step(Address::ZERO), dummy_step(Address::ZERO)];
        let executor = MultiBlockExecutor::new(&steps, None);

        assert!(!executor.is_multi_block());
        assert_eq!(executor.max_block_span(), 0);

        let groups = executor.grouped_steps();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[&0].len(), 2);
    }

    #[test]
    fn test_multi_block_grouping() {
        let steps = vec![
            dummy_step(Address::ZERO),
            dummy_step(Address::ZERO),
            dummy_step(Address::ZERO),
        ];
        let offsets = vec![0, 0, 1]; // First two in block 0, third in block 1
        let executor = MultiBlockExecutor::new(&steps, Some(&offsets));

        assert!(executor.is_multi_block());
        assert_eq!(executor.max_block_span(), 1);

        let groups = executor.grouped_steps();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&0].len(), 2);
        assert_eq!(groups[&1].len(), 1);
    }

    #[test]
    fn test_to_bundles() {
        let steps = vec![dummy_step(Address::ZERO), dummy_step(Address::ZERO)];
        let offsets = vec![0, 1];
        let executor = MultiBlockExecutor::new(&steps, Some(&offsets));

        let mut signed = BTreeMap::new();
        signed.insert(0, vec![AlloyBytes::from(vec![0xaa, 0xaa])]);
        signed.insert(1, vec![AlloyBytes::from(vec![0xbb, 0xbb])]);

        let bundles = executor.to_bundles(100, &signed, 9999);
        assert_eq!(bundles.len(), 2);
        assert_eq!(bundles[0].0, 100); // target block 100
        assert_eq!(bundles[1].0, 101); // target block 101
        assert_eq!(bundles[0].1.block_number, "0x64");
        assert_eq!(bundles[1].1.block_number, "0x65");
        assert_eq!(bundles[0].1.txs, vec!["0xaaaa".to_string()]);
        assert_eq!(bundles[1].1.txs, vec!["0xbbbb".to_string()]);
    }

    #[test]
    fn test_advance_block_env() {
        let mut block_num = 100u64;
        let mut timestamp = 1000u64;

        advance_block_env(&mut block_num, &mut timestamp, 2);
        assert_eq!(block_num, 101);
        assert_eq!(timestamp, 1002);

        advance_block_env(&mut block_num, &mut timestamp, 12);
        assert_eq!(block_num, 102);
        assert_eq!(timestamp, 1014);
    }

    #[test]
    fn test_block_time_for_chain() {
        assert_eq!(block_time_for_chain(1), 12);
        assert_eq!(block_time_for_chain(8453), 2);
        assert_eq!(block_time_for_chain(10), 2);
        assert_eq!(block_time_for_chain(42161), 1);
        assert_eq!(block_time_for_chain(999), 12); // unknown
    }
}
