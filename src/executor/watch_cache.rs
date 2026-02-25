use alloy::primitives::{Address, B256};

use crate::solver::objectives::ExploitParams;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
static LAST_WATCH_CACHE_NOW_MS: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct WatchCacheItem {
    pub target: Address,
    pub objective: String,
    pub fingerprint: B256,
    pub params: ExploitParams,
    pub original_solve_block: u64,
    pub original_solve_ms: u128,
    pub last_checked_block: u64,
    pub attempts: u32,
}

#[derive(Debug, Default)]
pub struct WatchCache {
    items: Vec<WatchCacheItem>,
}

impl WatchCache {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn contains_fingerprint(&self, fingerprint: B256) -> bool {
        self.items
            .iter()
            .any(|entry| entry.fingerprint == fingerprint)
    }

    /// Inserts a watch item if its fingerprint is not already present.
    /// If `max_items` is exceeded, evicts oldest entries (front) and keeps newest.
    pub fn insert_if_absent_with_capacity(
        &mut self,
        item: WatchCacheItem,
        max_items: usize,
    ) -> bool {
        if self.contains_fingerprint(item.fingerprint) {
            return false;
        }
        if max_items > 0 && self.items.len() >= max_items {
            let len = self.items.len();
            // Drain enough items to make room for this insert (keep newest `max_items-1`).
            let keep = max_items.saturating_sub(1);
            let drain_to = len.saturating_sub(keep);
            if drain_to > 0 {
                self.items.drain(0..drain_to);
            }
        }
        self.items.push(item);
        true
    }

    pub fn remove_by_fingerprint(&mut self, fingerprint: B256) {
        self.items.retain(|entry| entry.fingerprint != fingerprint);
    }

    pub fn remove_target_fingerprint(&mut self, target: Address, fingerprint: B256) {
        self.items
            .retain(|entry| !(entry.target == target && entry.fingerprint == fingerprint));
    }

    /// Selects up to `per_block` candidates to recheck for `head`, updating bookkeeping in-place.
    /// Items already checked for `head` are skipped.
    pub fn select_for_head(
        &mut self,
        head: u64,
        per_block: usize,
        max_attempts: u32,
    ) -> Vec<WatchCacheItem> {
        self.items.retain(|item| item.attempts < max_attempts);
        let mut selected = Vec::new();
        for item in self.items.iter_mut() {
            if selected.len() >= per_block {
                break;
            }
            if item.last_checked_block >= head {
                continue;
            }
            item.last_checked_block = head;
            item.attempts = item.attempts.saturating_add(1);
            selected.push(item.clone());
        }
        selected
    }
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_watch_cache_now_ms(sample)
}

fn normalize_watch_cache_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_WATCH_CACHE_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_WATCH_CACHE_NOW_MS.compare_exchange_weak(
            prev,
            normalized,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return normalized,
            Err(actual) => prev = actual,
        }
    }
}

/// Background "wait-and-fire" watch-cache rechecker.
///
/// This is intentionally out of `main.rs` so the findings consumer ordering invariants are
/// auditable (SAT persistence before executor dispatch) without being confused by background
/// retry loops.
pub fn spawn_watch_cache_rechecker(
    watch_cache: Arc<Mutex<WatchCache>>,
    executor: Arc<crate::executor::Executor>,
    latest_head_hint: Arc<AtomicU64>,
    contested_tip_cache: Arc<Mutex<crate::executor::tip_auto_scaler::ContestedTipCache>>,
    submission_enabled: bool,
    per_block: usize,
    max_attempts: u32,
) {
    tokio::spawn(async move {
        let mut last_head = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;

            if !submission_enabled {
                continue;
            }
            if crate::utils::rpc::global_rpc_cooldown_active() {
                continue;
            }

            let head = latest_head_hint.load(Ordering::Relaxed);
            if head == 0 || head == last_head {
                continue;
            }
            last_head = head;

            let candidates = {
                let mut guard = watch_cache.lock().await;
                guard.select_for_head(head, per_block, max_attempts)
            };

            for item in candidates {
                println!(
                    "[WATCH] Re-checking cached SAT payload: target={:?} objective={} head={} attempts={} original_solve={}ms@{} fingerprint={:#x}",
                    item.target,
                    item.objective,
                    head,
                    item.attempts,
                    item.original_solve_ms,
                    item.original_solve_block,
                    item.fingerprint
                );
                let tip_auto_scale_contested = {
                    let mut guard = contested_tip_cache.lock().await;
                    guard.is_contested(item.target, head)
                };
                let feedback = executor
                    .execute_attack(
                        item.params.clone(),
                        item.target,
                        crate::executor::AttackExecutionContext {
                            target_solve_block: head,
                            solve_duration_ms: 0,
                            require_late_solve_preflight: false,
                            solve_completed_ms: now_ms(),
                            tip_auto_scale_contested,
                            verified_shadow_report: None,
                        },
                    )
                    .await;
                if crate::executor::builder_outcomes_have_competition_hint(
                    &feedback.builder_outcomes,
                ) {
                    let mut guard = contested_tip_cache.lock().await;
                    guard.mark_contested(item.target, head);
                }

                if matches!(
                    feedback.outcome,
                    crate::executor::AttackOutcome::Sent
                        | crate::executor::AttackOutcome::SimulatedOnly
                ) {
                    let mut guard = watch_cache.lock().await;
                    guard.remove_by_fingerprint(item.fingerprint);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_normalize_watch_cache_now_ms_never_returns_zero() {
        super::LAST_WATCH_CACHE_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_watch_cache_now_ms(None), 1);
        assert!(super::normalize_watch_cache_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_watch_cache_now_ms_clamps_clock_regression() {
        super::LAST_WATCH_CACHE_NOW_MS.store(500, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_watch_cache_now_ms(Some(450)), 500);
        assert_eq!(super::normalize_watch_cache_now_ms(Some(700)), 700);
    }
}
