//! Anchor Test: Distributed State Hydration wiring (HYDRATION_RPC_URLS pool build).

#[test]
fn test_build_hydration_provider_pool_dedupes_and_preserves_primary_first() {
    let old = std::env::var("HYDRATION_RPC_URLS").ok();
    std::env::set_var(
        "HYDRATION_RPC_URLS",
        "http://localhost:8546, http://localhost:8546, http://localhost:8547",
    );

    let (pool, urls) =
        dark_solver::utils::rpc::build_hydration_provider_pool("http://localhost:8545")
            .expect("pool build");

    if let Some(prev) = old {
        std::env::set_var("HYDRATION_RPC_URLS", prev);
    } else {
        std::env::remove_var("HYDRATION_RPC_URLS");
    }

    assert_eq!(pool.len(), 3);
    assert_eq!(urls.len(), 3);
    assert_eq!(urls[0], "http://localhost:8545");
}
