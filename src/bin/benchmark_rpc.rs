use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use std::time::Instant;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env via the project's own env_guard (no external dotenv crate needed)
    dark_solver::utils::env_guard::harden_env_setup();

    let primary = std::env::var("ETH_RPC_URL").unwrap_or_default();
    let hydration = std::env::var("HYDRATION_RPC_URLS").unwrap_or_default();

    let mut urls: Vec<String> = vec![];
    if !primary.is_empty() {
        urls.push(primary);
    }
    for url in hydration.split(',') {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    println!("Benchmarking {} RPC endpoints...", urls.len());
    println!("{:<60} | {:<10} | {:<10}", "URL", "Latency", "Block");
    println!("{}", "-".repeat(86));

    let mut results = vec![];

    for url in urls {
        let provider = ProviderBuilder::new().on_http(url.parse()?);
        let start = Instant::now();
        match tokio::time::timeout(Duration::from_secs(5), provider.get_block_number()).await {
            Ok(Ok(block)) => {
                let duration = start.elapsed();
                let ms = duration.as_millis();
                println!("{:<60} | {:<10}ms | #{}", url, ms, block);
                results.push((url, ms, block));
            }
            Ok(Err(e)) => {
                println!("{:<60} | {:<10} | ERROR: {}", url, "FAIL", e);
            }
            Err(_) => {
                println!("{:<60} | {:<10} | TIMEOUT", url, "FAIL");
            }
        }
    }

    results.sort_by_key(|k| k.1);

    if let Some((best_url, best_ms, _)) = results.first() {
        println!("\n🏆 FASTEST RPC: {} ({}ms)", best_url, best_ms);
        println!("Update your .env ETH_RPC_URL to use this endpoint for lower latency.");
    } else {
        println!("\n❌ All RPCs failed or timed out.");
    }

    Ok(())
}
