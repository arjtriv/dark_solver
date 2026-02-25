//! Anchor: watch-cache trap retains slow SAT payloads and rechecks them on new heads
//! without re-solving (selection/attempt accounting is deterministic).

use alloy::primitives::{address, B256};
use dark_solver::executor::watch_cache::{WatchCache, WatchCacheItem};
use dark_solver::solver::objectives::{ExploitParams, ExploitStep};
use revm::primitives::{Address, Bytes, U256};

fn dummy_params() -> ExploitParams {
    ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: vec![ExploitStep {
            target: Address::ZERO,
            call_data: Bytes::new(),
            execute_if: None,
        }],
        expected_profit: None,
        block_offsets: None,
    }
}

#[test]
fn watch_cache_select_for_head_increments_attempts_and_marks_checked() {
    let mut cache = WatchCache::default();
    let fp1 = B256::from([1u8; 32]);
    let fp2 = B256::from([2u8; 32]);

    let base = WatchCacheItem {
        target: address!("0000000000000000000000000000000000000001"),
        objective: "deep".to_string(),
        fingerprint: fp1,
        params: dummy_params(),
        original_solve_block: 100,
        original_solve_ms: 35_000,
        last_checked_block: 100,
        attempts: 0,
    };
    assert!(cache.insert_if_absent_with_capacity(base.clone(), 96));
    assert!(cache.insert_if_absent_with_capacity(
        WatchCacheItem {
            fingerprint: fp2,
            ..base.clone()
        },
        96
    ));

    let selected = cache.select_for_head(101, 1, 10);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].last_checked_block, 101);
    assert_eq!(selected[0].attempts, 1);

    // Same head can select remaining unchecked items, but never repeats already-checked ones.
    let selected_again = cache.select_for_head(101, 10, 10);
    assert_eq!(selected_again.len(), 1);
    assert_eq!(selected_again[0].last_checked_block, 101);
    assert_eq!(selected_again[0].attempts, 1);
    let selected_third = cache.select_for_head(101, 10, 10);
    assert_eq!(selected_third.len(), 0);

    // Next head: can select again.
    let selected_next = cache.select_for_head(102, 2, 10);
    assert!(!selected_next.is_empty());
}

#[test]
fn watch_cache_eviction_and_removal_are_fingerprint_based() {
    let mut cache = WatchCache::default();
    let fp1 = B256::from([1u8; 32]);
    let fp2 = B256::from([2u8; 32]);

    let base = WatchCacheItem {
        target: address!("0000000000000000000000000000000000000001"),
        objective: "deep".to_string(),
        fingerprint: fp1,
        params: dummy_params(),
        original_solve_block: 100,
        original_solve_ms: 35_000,
        last_checked_block: 100,
        attempts: 0,
    };
    assert!(cache.insert_if_absent_with_capacity(base.clone(), 1));
    // Capacity=1: inserting a second item should evict the first.
    assert!(cache.insert_if_absent_with_capacity(
        WatchCacheItem {
            fingerprint: fp2,
            ..base.clone()
        },
        1
    ));
    assert_eq!(cache.len(), 1);
    assert!(cache.contains_fingerprint(fp2));
    assert!(!cache.contains_fingerprint(fp1));

    cache.remove_by_fingerprint(fp2);
    assert!(cache.is_empty());
}
