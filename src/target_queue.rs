use alloy::primitives::Address;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetPriority {
    /// Operator override: always execute first.
    Manual,
    /// High-capital / time-sensitive: must bypass dust backlog.
    Hot,
    /// Default lane.
    Normal,
    /// Lowest lane: acceptable to drop/evict under pressure.
    Dust,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetItem {
    pub address: Address,
    pub priority: TargetPriority,
}

struct TargetQueueState {
    manual: VecDeque<Address>,
    hot: VecDeque<Address>,
    normal: VecDeque<Address>,
    dust: VecDeque<Address>,
    queued: HashMap<Address, TargetPriority>,
    max_len: usize,
    closed: bool,
}

impl TargetQueueState {
    fn len(&self) -> usize {
        self.manual
            .len()
            .saturating_add(self.hot.len())
            .saturating_add(self.normal.len())
            .saturating_add(self.dust.len())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn pop_next(&mut self) -> Option<TargetItem> {
        if let Some(addr) = self.manual.pop_front() {
            self.queued.remove(&addr);
            return Some(TargetItem {
                address: addr,
                priority: TargetPriority::Manual,
            });
        }
        if let Some(addr) = self.hot.pop_front() {
            self.queued.remove(&addr);
            return Some(TargetItem {
                address: addr,
                priority: TargetPriority::Hot,
            });
        }
        if let Some(addr) = self.normal.pop_front() {
            self.queued.remove(&addr);
            return Some(TargetItem {
                address: addr,
                priority: TargetPriority::Normal,
            });
        }
        if let Some(addr) = self.dust.pop_front() {
            self.queued.remove(&addr);
            return Some(TargetItem {
                address: addr,
                priority: TargetPriority::Dust,
            });
        }
        None
    }

    fn evict_one_lowest(&mut self, allow_evict_normal: bool) -> bool {
        // Evict the newest low-priority work first. This keeps earlier backlog stable.
        if let Some(addr) = self.dust.pop_back() {
            self.queued.remove(&addr);
            return true;
        }
        if allow_evict_normal {
            if let Some(addr) = self.normal.pop_back() {
                self.queued.remove(&addr);
                return true;
            }
        }
        false
    }

    fn push(&mut self, address: Address, priority: TargetPriority) {
        match priority {
            TargetPriority::Manual => self.manual.push_back(address),
            TargetPriority::Hot => self.hot.push_back(address),
            TargetPriority::Normal => self.normal.push_back(address),
            TargetPriority::Dust => self.dust.push_back(address),
        }
    }

    fn priority_rank(priority: TargetPriority) -> u8 {
        match priority {
            TargetPriority::Manual => 3,
            TargetPriority::Hot => 2,
            TargetPriority::Normal => 1,
            TargetPriority::Dust => 0,
        }
    }

    fn is_higher_priority(next: TargetPriority, current: TargetPriority) -> bool {
        Self::priority_rank(next) > Self::priority_rank(current)
    }

    fn remove_from_lane(&mut self, address: Address, priority: TargetPriority) -> bool {
        let lane = match priority {
            TargetPriority::Manual => &mut self.manual,
            TargetPriority::Hot => &mut self.hot,
            TargetPriority::Normal => &mut self.normal,
            TargetPriority::Dust => &mut self.dust,
        };
        let Some(index) = lane.iter().position(|queued| *queued == address) else {
            return false;
        };
        lane.remove(index).is_some()
    }

    fn promote(&mut self, address: Address, next_priority: TargetPriority) -> bool {
        let Some(current_priority) = self.queued.get(&address).copied() else {
            return false;
        };
        if !Self::is_higher_priority(next_priority, current_priority) {
            return false;
        }
        if !self.remove_from_lane(address, current_priority) {
            return false;
        }
        self.queued.insert(address, next_priority);
        self.push(address, next_priority);
        true
    }
}

struct TargetQueueInner {
    state: Mutex<TargetQueueState>,
    notify: Notify,
}

#[derive(Clone)]
pub struct TargetQueueSender {
    inner: Arc<TargetQueueInner>,
}

pub struct TargetQueueReceiver {
    inner: Arc<TargetQueueInner>,
}

pub struct TargetQueue;

impl TargetQueue {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(max_len: usize) -> (TargetQueueSender, TargetQueueReceiver) {
        let max_len = std::cmp::max(1, max_len);
        let inner = Arc::new(TargetQueueInner {
            state: Mutex::new(TargetQueueState {
                manual: VecDeque::new(),
                hot: VecDeque::new(),
                normal: VecDeque::new(),
                dust: VecDeque::new(),
                queued: HashMap::new(),
                max_len,
                closed: false,
            }),
            notify: Notify::new(),
        });
        (
            TargetQueueSender {
                inner: Arc::clone(&inner),
            },
            TargetQueueReceiver { inner },
        )
    }
}

impl TargetQueueSender {
    /// Enqueue a target for solving.
    ///
    /// Returns `true` if the address was accepted or promoted in-place, `false`
    /// if it was dropped (queue full, queue closed, or already queued at an
    /// equal/higher priority).
    pub async fn enqueue(&self, address: Address, priority: TargetPriority) -> bool {
        let mut state = self.inner.state.lock().await;
        if state.closed {
            return false;
        }
        if state.queued.contains_key(&address) {
            let promoted = state.promote(address, priority);
            drop(state);
            if promoted {
                self.inner.notify.notify_one();
            }
            return promoted;
        }

        while state.len() >= state.max_len {
            let evicted = match priority {
                TargetPriority::Manual => state.evict_one_lowest(true),
                TargetPriority::Hot => state.evict_one_lowest(true),
                TargetPriority::Normal => state.evict_one_lowest(false),
                TargetPriority::Dust => false,
            };
            if !evicted {
                return false;
            }
        }

        state.queued.insert(address, priority);
        state.push(address, priority);
        drop(state);
        self.inner.notify.notify_one();
        true
    }

    pub async fn close(&self) {
        let mut state = self.inner.state.lock().await;
        state.closed = true;
        drop(state);
        self.inner.notify.notify_waiters();
    }
}

impl TargetQueueReceiver {
    pub async fn recv(&mut self) -> Option<TargetItem> {
        loop {
            let notified = {
                let mut state = self.inner.state.lock().await;
                if let Some(item) = state.pop_next() {
                    return Some(item);
                }
                if state.closed && state.is_empty() {
                    return None;
                }
                self.inner.notify.notified()
            };
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TargetPriority, TargetQueue};
    use alloy::primitives::Address;

    #[tokio::test]
    async fn target_queue_promotes_existing_item_to_hot() {
        let (tx, mut rx) = TargetQueue::new(8);
        let dust = Address::new([0x11; 20]);
        let normal = Address::new([0x22; 20]);

        assert!(tx.enqueue(dust, TargetPriority::Dust).await);
        assert!(tx.enqueue(normal, TargetPriority::Normal).await);
        assert!(tx.enqueue(dust, TargetPriority::Hot).await);

        let first = rx.recv().await.expect("promoted hot target");
        let second = rx.recv().await.expect("remaining normal target");

        assert_eq!(first.address, dust);
        assert_eq!(first.priority, TargetPriority::Hot);
        assert_eq!(second.address, normal);
        assert_eq!(second.priority, TargetPriority::Normal);

        tx.close().await;
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn target_queue_promotes_hot_to_manual_without_duplication() {
        let (tx, mut rx) = TargetQueue::new(8);
        let target = Address::new([0x33; 20]);
        let peer_hot = Address::new([0x44; 20]);

        assert!(tx.enqueue(target, TargetPriority::Hot).await);
        assert!(tx.enqueue(peer_hot, TargetPriority::Hot).await);
        assert!(tx.enqueue(target, TargetPriority::Manual).await);
        assert!(!tx.enqueue(target, TargetPriority::Hot).await);

        let first = rx.recv().await.expect("manual target");
        let second = rx.recv().await.expect("peer hot target");

        assert_eq!(first.address, target);
        assert_eq!(first.priority, TargetPriority::Manual);
        assert_eq!(second.address, peer_hot);
        assert_eq!(second.priority, TargetPriority::Hot);

        tx.close().await;
        assert!(rx.recv().await.is_none());
    }
}
