use std::fs;

#[test]
fn test_sequencer_ingestion_defaults_and_tracked_maps_are_backpressure_aware() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("sequencer_ws_default_max_txs_per_sec(chain_id: u64)")
            && source.contains("load_sequencer_ws_ingestion_max_txs_per_sec_for_chain(chain_id: u64)")
            && source.contains("sequencer_ws_default_max_addrs_per_tx(chain_id: u64)")
            && source.contains("load_sequencer_ws_ingestion_address_cooldown_ms_for_chain(chain_id: u64)"),
        "sequencer ingestion defaults must derive from per-chain timing instead of static open-throttle values"
    );
    assert!(
        source.contains("load_sequencer_ws_ingestion_tracked_addrs_cap(")
            && source.contains("SEQUENCER_WS_TRACKED_ADDRS_CAP"),
        "sequencer ingestion must expose a tracked-address cap for map backpressure"
    );
    assert!(
        source.contains("last_sent_ms.len() >= tracked_addrs_cap")
            && source.contains("last_probe_ms.len() >= tracked_addrs_cap"),
        "pending ingestion must gate new tracked addresses when backpressure cap is reached"
    );
}
