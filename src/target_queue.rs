use alloy::primitives::Address;
use std::collections::{HashSet, VecDeque};
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
    queued: HashSet<Address>,
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
                queued: HashSet::new(),
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
    /// Returns `true` if the address was accepted (enqueued), `false` if it was
    /// dropped (already queued, queue full, or queue closed).
    pub async fn enqueue(&self, address: Address, priority: TargetPriority) -> bool {
        let mut state = self.inner.state.lock().await;
        if state.closed {
            return false;
        }
        if state.queued.contains(&address) {
            return false;
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

        state.queued.insert(address);
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
