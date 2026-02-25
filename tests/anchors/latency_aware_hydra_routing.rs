use alloy::providers::ProviderBuilder;
use dark_solver::utils::rpc::{
    global_rpc_cooldown_remaining_ms, run_with_hydration_pool_retry, HydrationProviderPool,
};
use std::time::Instant;

#[tokio::test(flavor = "current_thread")]
async fn test_latency_aware_hydra_routing_prefers_low_ewma() {
    let p1 = ProviderBuilder::new().on_http("http://localhost:9545".parse().unwrap());
    let p2 = ProviderBuilder::new().on_http("http://localhost:9546".parse().unwrap());
    let p3 = ProviderBuilder::new().on_http("http://localhost:9547".parse().unwrap());
    let pool = HydrationProviderPool::new(p1, vec![p2, p3]);

    // Seed EWMAs: idx=1 is the best.
    pool.observe_latency_ms(0, 200);
    pool.observe_latency_ms(1, 50);
    pool.observe_latency_ms(2, 120);

    let (idx, _) = pool.pick_ready().await;
    assert_eq!(idx, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn test_single_provider_rate_limit_does_not_arm_global_cooldown_and_respects_local_cooldown()
{
    let before = global_rpc_cooldown_remaining_ms();

    let p1 = ProviderBuilder::new().on_http("http://localhost:9645".parse().unwrap());
    let pool = HydrationProviderPool::new(p1, vec![]);

    // Force a rate-limit error with a tiny Retry-After so the second attempt must wait locally
    // without stalling the entire system via the global cooldown.
    let started = Instant::now();
    let err = run_with_hydration_pool_retry(&pool, 2, "anchor rate limit", move |_p| async move {
        Err::<(), _>(anyhow::anyhow!(
            "HTTP 429 Too Many Requests; retry-after: 10ms"
        ))
    })
    .await
    .unwrap_err();
    let _ = err;

    // Second attempt should be delayed by per-endpoint cooldown (Retry-After hint).
    assert!(
        started.elapsed().as_millis() >= 8,
        "per-endpoint cooldown should delay retry for a single-provider pool"
    );

    // If global cooldown was inactive, it must remain inactive (no "global stalling").
    let after = global_rpc_cooldown_remaining_ms();
    if before == 0 {
        assert_eq!(after, 0);
    }
}
