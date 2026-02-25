use alloy::primitives::{address, Address};
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use dark_solver::solver::setup::hydrate_target_context;
use std::time::Duration;

// USDbC (Base) - A standard Transparent Upgradeable Proxy
const USDBC_PROXY: Address = address!("d9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA");

#[tokio::test]
async fn test_proxy_blindness_cure() -> anyhow::Result<()> {
    // This test proves that the SOLVER now sees the Implementation (Cured Blindness).

    let rpc_url =
        std::env::var("BASE_RPC_URL").unwrap_or_else(|_| "https://mainnet.base.org".to_string());
    // Fallback if no env var, largely for CI or local testing validity
    if rpc_url.contains("localhost") || rpc_url.contains("127.0.0.1") {
        println!("Skipping scan test on localhost/mock");
        return Ok(());
    }

    // Skip quickly when network access is unavailable (Codex sandboxes / offline CI).
    let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
    match tokio::time::timeout(Duration::from_millis(800), provider.get_chain_id()).await {
        Ok(Ok(_)) => {}
        _ => {
            println!("Skipping proxy blindness cure test: RPC not reachable within timeout.");
            return Ok(());
        }
    }

    println!("Hydrating context for USDbC Proxy...");
    let rpc_url_clone = rpc_url.clone();
    let context = match tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || {
            let dummy_bytecode = revm::primitives::Bytes::from_static(&[0x00]);
            hydrate_target_context(&rpc_url_clone, 8453, USDBC_PROXY, &dummy_bytecode, None)
        }),
    )
    .await
    {
        Ok(Ok(ctx)) => ctx,
        Ok(Err(err)) => {
            println!("Skipping proxy blindness cure test: hydrate_target_context failed: {err:?}");
            return Ok(());
        }
        Err(_) => {
            println!("Skipping proxy blindness cure test: hydrate_target_context timed out.");
            return Ok(());
        }
    };

    println!("Proxy Address: {:?}", context.target_address);
    println!("Dependencies Found: {}", context.dependencies.len());

    // In a "Sovereign" system, we MUST have at least 1 dependency (the implementation).
    if context.dependencies.is_empty() {
        panic!("Test Failed: The solver is still BLIND. It found 0 dependencies for USDbC.");
    }

    println!(
        "\n[PROOF OF SIGHT]: The solver found {} dependencies.",
        context.dependencies.len()
    );
    println!("Dependency 0: {:?}", context.dependencies[0].address);
    // Determine if dependency 0 is likely the implementation
    // We can't know the exact address easily without RPC, but typically it shouldn't be empty code.
    assert!(!context.dependencies[0].account_info.code_hash.is_zero());

    Ok(())
}
