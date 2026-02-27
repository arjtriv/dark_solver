use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{anyhow, Context, Result};
use dark_solver::engine::objective_catalog::build_objectives;
use dark_solver::engine::runner::run_objectives_parallel;
use dark_solver::engine::setup::hydrate_target_context;
use dark_solver::utils::rpc::RobustRpc;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
struct Args {
    address: Address,
    rpc_url: String,
    chain_id: Option<u64>,
    objective_allowlist: Option<String>,
}

fn print_usage() {
    eprintln!(
        "usage: deep_sniper (single-target audit) --address <0x...> [--rpc-url <url>] [--chain-id <id>] [--objective-allowlist <csv>]\n\
         env fallback: ETH_RPC_URL or RPC_URL"
    );
}

fn parse_args_from_iter<I, S>(iter: I) -> Result<Args>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut address_raw: Option<String> = None;
    let mut rpc_url = std::env::var("ETH_RPC_URL")
        .ok()
        .or_else(|| std::env::var("RPC_URL").ok());
    let mut chain_id: Option<u64> = None;
    let mut objective_allowlist: Option<String> = None;

    let mut iter = iter.into_iter().map(Into::into);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--address" | "-a" => {
                address_raw = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?,
                );
            }
            "--rpc-url" | "-r" => {
                rpc_url = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?,
                );
            }
            "--chain-id" | "-c" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                chain_id = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow!("invalid chain id '{raw}': {e}"))?,
                );
            }
            "--objective-allowlist" | "--allowlist" => {
                objective_allowlist = Some(
                    iter.next()
                        .ok_or_else(|| anyhow!("missing value for {arg}"))?,
                );
            }
            other => return Err(anyhow!("unknown argument '{other}'")),
        }
    }

    let address_raw = address_raw.ok_or_else(|| anyhow!("--address is required"))?;
    let address = Address::from_str(&address_raw)
        .map_err(|e| anyhow!("invalid address '{address_raw}': {e}"))?;
    let rpc_url =
        rpc_url.ok_or_else(|| anyhow!("--rpc-url (or ETH_RPC_URL/RPC_URL env) is required"))?;

    Ok(Args {
        address,
        rpc_url,
        chain_id,
        objective_allowlist,
    })
}

fn parse_args() -> Result<Args> {
    parse_args_from_iter(std::env::args().skip(1))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args().inspect_err(|_| print_usage())?;
    if let Some(allowlist) = &args.objective_allowlist {
        std::env::set_var("OBJECTIVE_ALLOWLIST", allowlist);
    }
    let chain_id = match args.chain_id {
        Some(id) => id,
        None => {
            let provider = ProviderBuilder::new().on_http(args.rpc_url.parse()?);
            match tokio::time::timeout(
                std::time::Duration::from_millis(1_500),
                provider.get_chain_id(),
            )
            .await
            {
                Ok(Ok(id)) => id,
                Ok(Err(err)) => {
                    return Err(anyhow!("failed to auto-detect chain id from RPC: {}", err));
                }
                Err(_) => {
                    return Err(anyhow!(
                        "timed out auto-detecting chain id from RPC; pass --chain-id explicitly"
                    ));
                }
            }
        }
    };

    println!("[AUDIT] target={:?} chain_id={}", args.address, chain_id);

    let (hydration_pool, _hydration_urls) =
        dark_solver::utils::rpc::build_hydration_provider_pool(&args.rpc_url)?;
    let bytecode = RobustRpc::get_code_with_hydration_pool_retry(&hydration_pool, args.address, 3)
        .await
        .context("failed to fetch target bytecode")?;
    if bytecode.is_empty() {
        return Err(anyhow!("target has empty bytecode: {:?}", args.address));
    }
    println!("[AUDIT] bytecode={} bytes", bytecode.len());

    let target_context = Arc::new(hydrate_target_context(
        &args.rpc_url,
        chain_id,
        Address::from_slice(args.address.as_slice()),
        &bytecode,
        None,
    ));
    let objectives = build_objectives(args.rpc_url.clone(), chain_id);

    let started = std::time::Instant::now();
    let findings = run_objectives_parallel(objectives, &bytecode, Some(target_context))
        .await
        .context("parallel objective runner failed")?;
    let elapsed_ms = started.elapsed().as_millis();
    println!("[AUDIT] solve_complete elapsed_ms={elapsed_ms}");

    if findings.is_empty() {
        return Err(anyhow!(
            "no SAT finding for {:?} (elapsed={}ms)",
            args.address,
            elapsed_ms
        ));
    }

    for (objective, params) in findings {
        println!("\n[AUDIT] objective={objective}");
        println!(
            "  flash_loan amount={} token={:?} provider={:?}",
            params.flash_loan_amount, params.flash_loan_token, params.flash_loan_provider
        );
        if let Some(profit) = params.expected_profit {
            println!("  expected_profit={profit}");
        }
        if let Some(offsets) = &params.block_offsets {
            println!("  block_offsets={offsets:?}");
        }
        for (idx, step) in params.steps.iter().enumerate() {
            println!(
                "  step={} target={:?} calldata=0x{}",
                idx + 1,
                step.target,
                hex::encode(step.call_data.as_ref())
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_args_from_iter, Args};
    use alloy::primitives::Address;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_env() {
        std::env::remove_var("ETH_RPC_URL");
        std::env::remove_var("RPC_URL");
        std::env::remove_var("OBJECTIVE_ALLOWLIST");
    }

    #[test]
    fn parse_args_from_iter_accepts_explicit_values() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let args = parse_args_from_iter([
            "--address",
            "0x1111111111111111111111111111111111111111",
            "--rpc-url",
            "https://rpc.example",
            "--chain-id",
            "8453",
        ])
        .expect("parse");

        assert_eq!(
            args,
            Args {
                address: Address::from([0x11; 20]),
                rpc_url: "https://rpc.example".to_string(),
                chain_id: Some(8453),
                objective_allowlist: None,
            }
        );
    }

    #[test]
    fn parse_args_from_iter_uses_rpc_env_fallback() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();
        std::env::set_var("ETH_RPC_URL", "https://env-rpc.example");

        let args =
            parse_args_from_iter(["--address", "0x2222222222222222222222222222222222222222"])
                .expect("parse");

        assert_eq!(args.address, Address::from([0x22; 20]));
        assert_eq!(args.rpc_url, "https://env-rpc.example");
        assert_eq!(args.chain_id, None);
        assert_eq!(args.objective_allowlist, None);

        clear_env();
    }

    #[test]
    fn parse_args_from_iter_accepts_objective_allowlist() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let args = parse_args_from_iter([
            "--address",
            "0x3333333333333333333333333333333333333333",
            "--rpc-url",
            "https://rpc.example",
            "--objective-allowlist",
            "generic,oracle",
        ])
        .expect("parse");

        assert_eq!(args.address, Address::from([0x33; 20]));
        assert_eq!(args.objective_allowlist.as_deref(), Some("generic,oracle"));
    }
}
