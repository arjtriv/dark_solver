use std::fs;

#[test]
fn test_dark_error_hierarchy_is_structured_and_wired() {
    let error_source = fs::read_to_string("src/error.rs").expect("src/error.rs must be readable");
    let config_source =
        fs::read_to_string("src/utils/config.rs").expect("src/utils/config.rs must be readable");
    let builders_source = fs::read_to_string("src/executor/builders.rs")
        .expect("src/executor/builders.rs must be readable");

    for needle in [
        "pub enum DarkError",
        "Math(#[from] Z3Error)",
        "Net(#[from] RpcError)",
        "Logic(#[from] InvariantWaitError)",
        "pub enum Z3Error",
        "pub enum RpcError",
        "pub enum InvariantWaitError",
    ] {
        assert!(
            error_source.contains(needle),
            "dark error hierarchy must contain `{needle}`"
        );
    }

    assert!(
        config_source.contains("InvariantWaitError::MissingConfig"),
        "config loader must lift missing env vars into InvariantWaitError"
    );
    assert!(
        config_source.contains("InvariantWaitError::InvalidConfig"),
        "config loader must lift invalid CHAIN_ID parse into InvariantWaitError"
    );
    assert!(
        !config_source.contains("anyhow::"),
        "config loader should avoid ad-hoc anyhow usage"
    );

    for needle in [
        "use crate::error::{Result, RpcError};",
        "async fn send_bundle(&self, bundle: &BundlePayload) -> Result<BundleResponse>;",
        "async fn secure_handshake(&self) -> Result<()>;",
        "pub async fn send_bundle(&self, bundle: &BundlePayload) -> Vec<Result<BundleResponse>>",
        "pub fn verify_private_transport_url(url: &str) -> Result<()>",
        "RpcError::InvalidUrl",
        "RpcError::Transport",
        "RpcError::PublicRpcEndpoint",
        "RpcError::BundleHandshakeRejected",
    ] {
        assert!(
            builders_source.contains(needle),
            "builder stack must contain `{needle}`"
        );
    }
    assert!(
        !builders_source.contains("anyhow::"),
        "builder stack should avoid ad-hoc anyhow usage"
    );
}
