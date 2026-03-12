use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use dark_solver::utils::cli::{extend_csv_strings, normalize_string_list, parse_u64_flag};
use std::time::Instant;
use tokio::time::Duration;

#[derive(Debug, PartialEq)]
struct Args {
    urls: Vec<String>,
    timeout_ms: u64,
    json: bool,
}

fn print_usage() {
    eprintln!(
        "usage: benchmark_rpc [--url <url>]... [--urls <csv>] [--timeout-ms <n>] [--json]\n\
         env fallback: ETH_RPC_URL and HYDRATION_RPC_URLS"
    );
}

fn collect_env_urls() -> Vec<String> {
    let mut urls = Vec::new();
    if let Ok(primary) = std::env::var("ETH_RPC_URL") {
        let trimmed = primary.trim();
        if !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }
    if let Ok(hydration) = std::env::var("HYDRATION_RPC_URLS") {
        extend_csv_strings(&mut urls, &hydration);
    }
    urls
}

fn parse_args_from_iter<I, S>(iter: I) -> anyhow::Result<Args>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut urls = collect_env_urls();
    let mut timeout_ms = 5_000u64;
    let mut json = false;

    let mut iter = iter.into_iter().map(Into::into);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--url" => {
                urls.push(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?,
                );
            }
            "--urls" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
                extend_csv_strings(&mut urls, &raw);
            }
            "--timeout-ms" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
                timeout_ms = parse_u64_flag(&raw, "timeout")?;
            }
            "--json" => {
                json = true;
            }
            other => return Err(anyhow::anyhow!("unknown argument '{other}'")),
        }
    }

    normalize_string_list(&mut urls);
    if urls.is_empty() {
        return Err(anyhow::anyhow!("no RPC URLs provided"));
    }

    Ok(Args {
        urls,
        timeout_ms,
        json,
    })
}

fn parse_args() -> anyhow::Result<Args> {
    parse_args_from_iter(std::env::args().skip(1))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env via the project's own env_guard (no external dotenv crate needed)
    dark_solver::utils::env_guard::harden_env_setup();

    let args = parse_args().inspect_err(|_| print_usage())?;

    if !args.json {
        println!("Benchmarking {} RPC endpoints...", args.urls.len());
        println!("{:<60} | {:<10} | {:<10}", "URL", "Latency", "Block");
        println!("{}", "-".repeat(86));
    }

    let mut results = vec![];

    for url in &args.urls {
        let provider = ProviderBuilder::new().on_http(url.parse()?);
        let start = Instant::now();
        match tokio::time::timeout(Duration::from_millis(args.timeout_ms), provider.get_block_number())
            .await
        {
            Ok(Ok(block)) => {
                let duration = start.elapsed();
                let ms = duration.as_millis();
                if !args.json {
                    println!("{:<60} | {:<10}ms | #{}", url, ms, block);
                }
                results.push(serde_json::json!({
                    "url": url,
                    "ok": true,
                    "latency_ms": ms,
                    "block": block.to_string(),
                }));
            }
            Ok(Err(e)) => {
                if !args.json {
                    println!("{:<60} | {:<10} | ERROR: {}", url, "FAIL", e);
                }
                results.push(serde_json::json!({
                    "url": url,
                    "ok": false,
                    "error": e.to_string(),
                }));
            }
            Err(_) => {
                if !args.json {
                    println!("{:<60} | {:<10} | TIMEOUT", url, "FAIL");
                }
                results.push(serde_json::json!({
                    "url": url,
                    "ok": false,
                    "error": "timeout",
                }));
            }
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "timeout_ms": args.timeout_ms,
                "results": results,
            }))?
        );
    } else if let Some(best) = results
        .iter()
        .filter(|entry| entry.get("ok").and_then(|v| v.as_bool()) == Some(true))
        .min_by_key(|entry| entry.get("latency_ms").and_then(|v| v.as_u64()).unwrap_or(u64::MAX))
    {
        let best_url = best.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        let best_ms = best
            .get("latency_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or_default();
        println!("\nFASTEST RPC: {} ({}ms)", best_url, best_ms);
        println!("Update your .env ETH_RPC_URL to use this endpoint for lower latency.");
    } else {
        println!("\nAll RPCs failed or timed out.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_args_from_iter, Args};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_env() {
        std::env::remove_var("ETH_RPC_URL");
        std::env::remove_var("HYDRATION_RPC_URLS");
    }

    #[test]
    fn parse_args_from_iter_collects_env_urls() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();
        std::env::set_var("ETH_RPC_URL", "https://primary.example");
        std::env::set_var(
            "HYDRATION_RPC_URLS",
            "https://backup-a.example,https://backup-b.example",
        );

        let args = parse_args_from_iter(Vec::<String>::new()).expect("parse");
        assert_eq!(
            args,
            Args {
                urls: vec![
                    "https://backup-a.example".to_string(),
                    "https://backup-b.example".to_string(),
                    "https://primary.example".to_string(),
                ],
                timeout_ms: 5_000,
                json: false,
            }
        );

        clear_env();
    }

    #[test]
    fn parse_args_from_iter_accepts_explicit_urls_and_json() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let args = parse_args_from_iter([
            "--url",
            "https://b.example",
            "--urls",
            "https://a.example,https://b.example",
            "--timeout-ms",
            "2500",
            "--json",
        ])
        .expect("parse");

        assert_eq!(
            args,
            Args {
                urls: vec![
                    "https://a.example".to_string(),
                    "https://b.example".to_string(),
                ],
                timeout_ms: 2_500,
                json: true,
            }
        );
    }

    #[test]
    fn parse_args_from_iter_rejects_empty_url_set() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let err = parse_args_from_iter(Vec::<String>::new()).expect_err("empty urls should fail");
        assert!(err.to_string().contains("no RPC URLs provided"));
    }
}
