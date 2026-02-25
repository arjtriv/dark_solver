//! Anchor: Sequencer websocket ingestion is OP-stack gated and env-configurable.

use dark_solver::scanner::sequencer_ws_ingestion_enabled_for_chain;

#[test]
fn anchor_sequencer_ws_ingestion_is_chain_gated_and_env_driven() {
    let old = std::env::var("SEQUENCER_WS_INGESTION_ENABLED").ok();

    std::env::set_var("SEQUENCER_WS_INGESTION_ENABLED", "true");
    assert!(sequencer_ws_ingestion_enabled_for_chain(8453));
    assert!(sequencer_ws_ingestion_enabled_for_chain(10));
    assert!(!sequencer_ws_ingestion_enabled_for_chain(1));

    std::env::set_var("SEQUENCER_WS_INGESTION_ENABLED", "false");
    assert!(!sequencer_ws_ingestion_enabled_for_chain(8453));

    match old {
        Some(v) => std::env::set_var("SEQUENCER_WS_INGESTION_ENABLED", v),
        None => std::env::remove_var("SEQUENCER_WS_INGESTION_ENABLED"),
    }
}
