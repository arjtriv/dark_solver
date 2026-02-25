use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_BLACKBOX_CAPACITY: usize = 5_000;
static LAST_BLACKBOX_NOW_MS: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize)]
pub struct BlackboxEvent {
    ts_ms: u64,
    category: String,
    message: String,
    details: Option<Value>,
}

#[derive(Debug, Serialize)]
struct BlackboxDump {
    reason: String,
    dumped_at_ms: u64,
    events: Vec<BlackboxEvent>,
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_blackbox_now_ms(sample)
}

fn normalize_blackbox_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_BLACKBOX_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_BLACKBOX_NOW_MS.compare_exchange_weak(
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

fn load_capacity() -> usize {
    std::env::var("BLACKBOX_BUFFER_SIZE")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(256, 100_000))
        .unwrap_or(DEFAULT_BLACKBOX_CAPACITY)
}

fn blackbox_state() -> &'static Mutex<VecDeque<BlackboxEvent>> {
    static STATE: OnceLock<Mutex<VecDeque<BlackboxEvent>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(VecDeque::with_capacity(load_capacity())))
}

fn dump_dir() -> PathBuf {
    std::env::var("BLACKBOX_DUMP_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn record(category: impl Into<String>, message: impl Into<String>, details: Option<Value>) {
    let lock = blackbox_state().lock();
    let mut state = match lock {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let cap = load_capacity();
    if state.len() >= cap {
        let _ = state.pop_front();
    }
    state.push_back(BlackboxEvent {
        ts_ms: now_ms(),
        category: category.into(),
        message: message.into(),
        details,
    });
}

pub fn dump(reason: &str) -> Option<PathBuf> {
    let snapshot = {
        let lock = blackbox_state().lock();
        let state = match lock {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.iter().cloned().collect::<Vec<_>>()
    };

    let payload = BlackboxDump {
        reason: reason.to_string(),
        dumped_at_ms: now_ms(),
        events: snapshot,
    };

    let file_name = format!("crash_report_{}.json", payload.dumped_at_ms);
    let mut path = dump_dir();
    path.push(file_name);
    let Ok(json) = serde_json::to_vec_pretty(&payload) else {
        return None;
    };
    if fs::write(&path, json).is_ok() {
        Some(path)
    } else {
        None
    }
}

pub fn install_panic_hook_once() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if INSTALLED.get().is_some() {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let msg = panic_info.to_string();
        record("panic", msg.clone(), None);
        if let Some(path) = dump("panic") {
            eprintln!("[BLACKBOX] panic dump written to {}", path.display());
        }
        previous(panic_info);
    }));
    let _ = INSTALLED.set(());
}

#[cfg(test)]
mod tests {
    use super::record;

    #[test]
    fn test_blackbox_record_does_not_panic() {
        record("test", "hello", None);
    }

    #[test]
    fn test_normalize_blackbox_now_ms_never_returns_zero() {
        super::LAST_BLACKBOX_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_blackbox_now_ms(None), 1);
        assert!(super::normalize_blackbox_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_blackbox_now_ms_clamps_clock_regressions() {
        super::LAST_BLACKBOX_NOW_MS.store(77, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_blackbox_now_ms(Some(50)), 77);
        assert_eq!(super::normalize_blackbox_now_ms(Some(120)), 120);
    }
}
