use std::fs;

#[test]
fn test_startup_rpc_probe_uses_validated_config_without_localhost_fallback() {
    let source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for startup RPC audit");

    let config_pos = source
        .find("let config = dark_solver::utils::config::Config::load()?;")
        .expect("startup must load config");
    let probe_pos = source
        .find("[STARTUP] Checking Connectivity to ETH_RPC_URL")
        .expect("startup connectivity probe must exist");

    assert!(
        config_pos < probe_pos,
        "startup must validate config before probing ETH_RPC_URL"
    );
    assert!(
        !source.contains(".unwrap_or_else(|_| \"http://localhost:8545\".parse().unwrap())"),
        "startup RPC probe must not silently fall back to localhost on malformed ETH_RPC_URL"
    );
    assert!(
        source.contains("validated ETH_RPC_URL failed to parse for startup probe"),
        "startup probe should fail closed if the validated URL cannot be re-parsed"
    );
}
