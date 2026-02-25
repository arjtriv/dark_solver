//! Anchor Test: config validates URL shape/schemes before the pipeline starts.

use std::fs;

#[test]
fn test_config_load_validates_rpc_ws_and_builder_urls() {
    let src = fs::read_to_string("src/utils/config.rs")
        .expect("src/utils/config.rs must be readable from workspace root");

    assert!(src.contains("fn validate_http_url("));
    assert!(src.contains("fn validate_ws_url("));

    // Required validation.
    assert!(src.contains("validate_http_url(\"ETH_RPC_URL\""));
    assert!(src.contains("validate_ws_url(\"ETH_WS_URL\""));

    // Optional validation.
    assert!(src.contains("validate_http_url(\"EXECUTION_RPC_URL\""));
    assert!(src.contains("validate_http_url(\"FLASHBOTS_RELAY_URL\""));
    assert!(src.contains("normalize_builder_url_for_validation"));
}
