use std::fs;

#[test]
fn test_distributed_hydra_ingestion_hydration_pool_and_batch_storage_probe_exist() {
    let fork = fs::read_to_string("src/fork_db.rs")
        .expect("src/fork_db.rs must be readable for hydra ingestion audit");
    assert!(
        fork.contains("build_hydration_provider_pool"),
        "ForkDB must build its hydration pool via the rpc layer (which reads HYDRATION_RPC_URLS)"
    );
    assert!(
        fork.contains("batch_get_storage_at_round_robin"),
        "ForkDB must provide batched storage probing for sparse hydration"
    );

    let rpc = fs::read_to_string("src/utils/rpc.rs")
        .expect("src/utils/rpc.rs must be readable for hydration pool audit");
    assert!(
        rpc.contains("HYDRATION_RPC_URLS"),
        "rpc layer must read HYDRATION_RPC_URLS for multi-RPC hydration"
    );
    assert!(
        rpc.contains("HydrationProviderPool"),
        "rpc layer must define a hydration provider pool"
    );
    assert!(
        rpc.contains("run_with_hydration_pool_retry"),
        "rpc layer must route hydration calls via pool retry"
    );
}
