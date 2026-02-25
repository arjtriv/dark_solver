//! Anchor Test: Priority Hot-Lane ingestion (sorted buffer) preserves ordering guarantees.

use alloy::primitives::Address;
use dark_solver::target_queue::{TargetPriority, TargetQueue};

#[tokio::test]
async fn test_target_queue_priority_ordering() {
    let (tx, mut rx) = TargetQueue::new(16);

    let dust = Address::new([0x11; 20]);
    let normal = Address::new([0x22; 20]);
    let hot = Address::new([0x33; 20]);
    let manual = Address::new([0x44; 20]);

    assert!(tx.enqueue(dust, TargetPriority::Dust).await);
    assert!(tx.enqueue(normal, TargetPriority::Normal).await);
    assert!(tx.enqueue(hot, TargetPriority::Hot).await);
    assert!(tx.enqueue(manual, TargetPriority::Manual).await);

    let a = rx.recv().await.expect("manual");
    let b = rx.recv().await.expect("hot");
    let c = rx.recv().await.expect("normal");
    let d = rx.recv().await.expect("dust");

    assert_eq!(a.address, manual);
    assert_eq!(a.priority, TargetPriority::Manual);
    assert_eq!(b.address, hot);
    assert_eq!(b.priority, TargetPriority::Hot);
    assert_eq!(c.address, normal);
    assert_eq!(c.priority, TargetPriority::Normal);
    assert_eq!(d.address, dust);
    assert_eq!(d.priority, TargetPriority::Dust);
}

#[tokio::test]
async fn test_target_queue_evicts_dust_for_hot() {
    let (tx, mut rx) = TargetQueue::new(3);

    let a = Address::new([0xA1; 20]);
    let b = Address::new([0xA2; 20]);
    let c = Address::new([0xA3; 20]);
    let hot = Address::new([0xB1; 20]);

    assert!(tx.enqueue(a, TargetPriority::Dust).await);
    assert!(tx.enqueue(b, TargetPriority::Dust).await);
    assert!(tx.enqueue(c, TargetPriority::Dust).await);

    // Queue full: enqueuing HOT should evict the newest dust (c) deterministically.
    assert!(tx.enqueue(hot, TargetPriority::Hot).await);

    let first = rx.recv().await.expect("hot");
    assert_eq!(first.address, hot);
    assert_eq!(first.priority, TargetPriority::Hot);

    let second = rx.recv().await.expect("dust a");
    let third = rx.recv().await.expect("dust b");
    assert_eq!(second.address, a);
    assert_eq!(third.address, b);
}
