use std::fs;

#[test]
fn test_executor_gas_solver_cache_is_wired() {
    let executor =
        fs::read_to_string("src/executor/mod.rs").expect("src/executor/mod.rs must be readable");

    assert!(
        executor.contains("GAS_SOLVER_CACHE_TTL_MS")
            && executor.contains("gas_opt_cache")
            && executor.contains("fn gas_opt_snapshot"),
        "executor must expose and wire a bounded gas-solver cache for hot-path attempts"
    );
    assert!(
        executor.contains("GasOptimalitySolver::from_provider_url(&self.rpc_url).await")
            && executor.contains("self.gas_opt_snapshot().await"),
        "executor should route dynamic gas pricing through cached snapshot fetch"
    );
}
