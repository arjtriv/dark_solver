use std::fs;

#[test]
fn test_predictive_mempool_hydration_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("read src/scanner.rs");

    assert!(
        scanner.contains("SEQUENCER_WS_PREDICTIVE_HYDRATION_ENABLED")
            && scanner.contains("SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_TRACKED")
            && scanner.contains("SEQUENCER_WS_PREDICTIVE_HYDRATION_TTL_MS")
            && scanner.contains("SEQUENCER_WS_PREDICTIVE_HYDRATION_MAX_PROBES_PER_HEAD")
            && scanner.contains("SEQUENCER_WS_PREDICTIVE_HYDRATION_CODE_TIMEOUT_MS"),
        "scanner must expose predictive hydration budgets for pending CREATE/CREATE2"
    );

    assert!(
        scanner.contains("predict_create_address")
            && scanner.contains("predict_create2_address")
            && scanner.contains("predict_eip2470_singleton_factory_create2")
            && scanner.contains("EIP2470_SINGLETON_FACTORY"),
        "scanner must predict CREATE and singleton-factory CREATE2 addresses from pending txs"
    );

    assert!(
        scanner.contains("subscribe_full_pending_transactions")
            && scanner.contains("subscribe_blocks")
            && scanner.contains("[HYDRATE] Predicted"),
        "scanner must connect pending-tx ingestion with head-driven code probes"
    );
}
