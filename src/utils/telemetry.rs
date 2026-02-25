use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_TELEMETRY_QUEUE_CAPACITY: usize = 512;
const DEFAULT_TELEMETRY_HTTP_TIMEOUT_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug)]
pub enum TelemetryLevel {
    Info,
    Success,
    Critical,
}

#[derive(Clone, Debug)]
struct TelemetryEvent {
    ts_ms: u64,
    level: TelemetryLevel,
    kind: String,
    message: String,
    details: Option<Value>,
}

#[derive(Clone, Debug)]
struct TelemetryConfig {
    discord_webhook_url: Option<String>,
    telegram_bot_token: Option<String>,
    telegram_chat_id: Option<String>,
    timeout_ms: u64,
}

static TELEMETRY_SENDER: OnceLock<SyncSender<TelemetryEvent>> = OnceLock::new();
static TELEMETRY_INIT_GUARD: OnceLock<Mutex<()>> = OnceLock::new();
static LAST_TELEMETRY_NOW_MS: AtomicU64 = AtomicU64::new(1);

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_telemetry_now_ms(sample)
}

fn normalize_telemetry_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_TELEMETRY_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_TELEMETRY_NOW_MS.compare_exchange_weak(
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

fn load_queue_capacity() -> usize {
    std::env::var("TELEMETRY_QUEUE_CAPACITY")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .map(|v| v.clamp(64, 16_384))
        .unwrap_or(DEFAULT_TELEMETRY_QUEUE_CAPACITY)
}

fn load_timeout_ms() -> u64 {
    std::env::var("TELEMETRY_HTTP_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(250, 15_000))
        .unwrap_or(DEFAULT_TELEMETRY_HTTP_TIMEOUT_MS)
}

fn load_config() -> TelemetryConfig {
    TelemetryConfig {
        discord_webhook_url: std::env::var("DISCORD_WEBHOOK_URL").ok(),
        telegram_bot_token: std::env::var("TELEGRAM_BOT_TOKEN").ok(),
        telegram_chat_id: std::env::var("TELEGRAM_CHAT_ID").ok(),
        timeout_ms: load_timeout_ms(),
    }
}

fn config_enabled(cfg: &TelemetryConfig) -> bool {
    cfg.discord_webhook_url
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty())
        || (cfg
            .telegram_bot_token
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
            && cfg
                .telegram_chat_id
                .as_deref()
                .is_some_and(|v| !v.trim().is_empty()))
}

fn fmt_level(level: TelemetryLevel) -> &'static str {
    match level {
        TelemetryLevel::Info => "INFO",
        TelemetryLevel::Success => "SUCCESS",
        TelemetryLevel::Critical => "CRITICAL",
    }
}

fn render_message(event: &TelemetryEvent) -> String {
    let mut msg = format!(
        "[{}][ts_ms={}] {}: {}",
        fmt_level(event.level),
        event.ts_ms,
        event.kind,
        event.message
    );
    if let Some(details) = &event.details {
        msg.push_str(" | details=");
        msg.push_str(&details.to_string());
    }
    msg
}

fn send_discord(client: &reqwest::blocking::Client, webhook_url: &str, event: &TelemetryEvent) {
    let payload = serde_json::json!({
        "content": render_message(event),
    });
    let _ = client.post(webhook_url).json(&payload).send();
}

fn send_telegram(
    client: &reqwest::blocking::Client,
    bot_token: &str,
    chat_id: &str,
    event: &TelemetryEvent,
) {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": render_message(event),
        "disable_web_page_preview": true,
    });
    let _ = client.post(url).json(&payload).send();
}

fn spawn_worker(cfg: TelemetryConfig) -> SyncSender<TelemetryEvent> {
    let (tx, rx) = sync_channel::<TelemetryEvent>(load_queue_capacity());
    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        while let Ok(event) = rx.recv() {
            if let Some(url) = cfg.discord_webhook_url.as_deref() {
                send_discord(&client, url, &event);
            }
            if let (Some(token), Some(chat_id)) = (
                cfg.telegram_bot_token.as_deref(),
                cfg.telegram_chat_id.as_deref(),
            ) {
                send_telegram(&client, token, chat_id, &event);
            }
        }
    });
    tx
}

pub fn init_telemetry() {
    if TELEMETRY_SENDER.get().is_some() {
        return;
    }
    let guard = TELEMETRY_INIT_GUARD.get_or_init(|| Mutex::new(()));
    let lock = guard.lock();
    let _guard = match lock {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if TELEMETRY_SENDER.get().is_some() {
        return;
    }
    let cfg = load_config();
    if !config_enabled(&cfg) {
        return;
    }
    let tx = spawn_worker(cfg);
    let _ = TELEMETRY_SENDER.set(tx);
}

pub fn emit(level: TelemetryLevel, kind: impl Into<String>, message: impl Into<String>) {
    emit_with_details(level, kind, message, None);
}

pub fn emit_with_details(
    level: TelemetryLevel,
    kind: impl Into<String>,
    message: impl Into<String>,
    details: Option<Value>,
) {
    if TELEMETRY_SENDER.get().is_none() {
        init_telemetry();
    }
    let Some(sender) = TELEMETRY_SENDER.get() else {
        return;
    };

    let event = TelemetryEvent {
        ts_ms: now_ms(),
        level,
        kind: kind.into(),
        message: message.into(),
        details,
    };
    match sender.try_send(event) {
        Ok(_) => {}
        Err(TrySendError::Full(_)) => {}
        Err(TrySendError::Disconnected(_)) => {}
    }
}

pub fn emit_success(kind: impl Into<String>, message: impl Into<String>) {
    emit(TelemetryLevel::Success, kind, message);
}

pub fn emit_critical(kind: impl Into<String>, message: impl Into<String>) {
    emit(TelemetryLevel::Critical, kind, message);
}

#[cfg(test)]
mod tests {
    use super::TelemetryLevel;

    #[test]
    fn test_fmt_level() {
        assert_eq!(super::fmt_level(TelemetryLevel::Info), "INFO");
        assert_eq!(super::fmt_level(TelemetryLevel::Success), "SUCCESS");
        assert_eq!(super::fmt_level(TelemetryLevel::Critical), "CRITICAL");
    }

    #[test]
    fn test_normalize_telemetry_now_ms_never_returns_zero() {
        super::LAST_TELEMETRY_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_telemetry_now_ms(None), 1);
        assert!(super::normalize_telemetry_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_telemetry_now_ms_clamps_clock_regressions() {
        super::LAST_TELEMETRY_NOW_MS.store(900, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_telemetry_now_ms(Some(850)), 900);
        assert_eq!(super::normalize_telemetry_now_ms(Some(1200)), 1200);
    }
}
