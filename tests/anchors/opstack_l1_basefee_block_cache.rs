//! Anchor: OP-stack L1 base fee retrieval is block-locked and cached (once per block height).

use dark_solver::executor::gas_solver::OpStackL1BaseFeeBlockCache;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn anchor_opstack_l1_basefee_cache_fetches_once_per_block() {
    let cache = OpStackL1BaseFeeBlockCache::new();
    let calls = Arc::new(AtomicUsize::new(0));

    let calls_a = Arc::clone(&calls);
    let v1 = cache
        .get_or_fetch(8453, 100, move |_| async move {
            calls_a.fetch_add(1, Ordering::SeqCst);
            Some(7u128)
        })
        .await;
    assert_eq!(v1, Some(7));

    // Same block must hit cache; the fetch closure must not be invoked.
    let calls_b = Arc::clone(&calls);
    let v2 = cache
        .get_or_fetch(8453, 100, move |_| async move {
            calls_b.fetch_add(1, Ordering::SeqCst);
            Some(999u128)
        })
        .await;
    assert_eq!(v2, Some(7));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Next block must re-fetch.
    let calls_c = Arc::clone(&calls);
    let v3 = cache
        .get_or_fetch(8453, 101, move |_| async move {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Some(9u128)
        })
        .await;
    assert_eq!(v3, Some(9));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
