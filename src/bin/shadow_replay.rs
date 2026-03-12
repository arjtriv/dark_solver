use alloy::primitives::Address;
use anyhow::Context;
use dark_solver::fork_db::ForkDB;
use dark_solver::solver::objectives::{
    ExploitObjective, GenericProfitObjective, OracleSpotObjective,
};
use dark_solver::solver::runner::run_objectives_parallel;
use dark_solver::utils::cli::{env_first_nonempty, parse_u64_flag};
use revm::DatabaseRef;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
struct Args {
    rpc_url: String,
    chain_id: u64,
    target: Address,
    block_number: u64,
    json: bool,
}

fn print_usage() {
    eprintln!(
        "usage: shadow_replay --rpc-url <url> --chain-id <id> --address <0x...> --block-number <n> [--json]\n\
         env fallback: ETH_RPC_URL or RPC_URL"
    );
}

fn parse_args_from_iter<I, S>(iter: I) -> anyhow::Result<Args>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut rpc_url = env_first_nonempty(&["ETH_RPC_URL", "RPC_URL"]);
    let mut chain_id: Option<u64> = None;
    let mut address: Option<Address> = None;
    let mut block_number: Option<u64> = None;
    let mut json = false;

    let mut iter = iter.into_iter().map(Into::into);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--rpc-url" | "-r" => {
                rpc_url = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?,
                );
            }
            "--chain-id" | "-c" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
                chain_id = Some(parse_u64_flag(&raw, "chain_id")?);
            }
            "--address" | "--target" | "-a" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
                address = Some(Address::from_str(&raw)?);
            }
            "--block-number" | "--block" | "-b" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))?;
                block_number = Some(parse_u64_flag(&raw, "block_number")?);
            }
            "--json" => {
                json = true;
            }
            other => return Err(anyhow::anyhow!("unknown argument '{other}'")),
        }
    }

    Ok(Args {
        rpc_url: rpc_url
            .ok_or_else(|| anyhow::anyhow!("--rpc-url (or ETH_RPC_URL/RPC_URL env) is required"))?,
        chain_id: chain_id.ok_or_else(|| anyhow::anyhow!("--chain-id is required"))?,
        target: address.ok_or_else(|| anyhow::anyhow!("--address is required"))?,
        block_number: block_number.ok_or_else(|| anyhow::anyhow!("--block-number is required"))?,
        json,
    })
}

fn parse_args() -> anyhow::Result<Args> {
    parse_args_from_iter(std::env::args().skip(1))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args().inspect_err(|_| print_usage())?;

    // Global pin for every ForkDB::new(...) call in this process.
    std::env::set_var("FORKDB_PIN_BLOCK_NUMBER", args.block_number.to_string());

    let fork_db = ForkDB::with_block_number(&args.rpc_url, args.block_number)?;
    let target_info = fork_db.basic_ref(args.target)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no account info for target {:?} at block {}",
            args.target,
            args.block_number
        )
    })?;
    let bytecode = target_info
        .code
        .map(|code| code.bytes())
        .ok_or_else(|| anyhow::anyhow!("target has no bytecode at block {}", args.block_number))?;
    if bytecode.is_empty() {
        return Err(anyhow::anyhow!(
            "target bytecode is empty at block {}",
            args.block_number
        ));
    }

    let target_context = Arc::new(dark_solver::solver::setup::hydrate_target_context(
        &args.rpc_url,
        args.chain_id,
        args.target,
        &bytecode,
        None,
    ));
    let objectives: Vec<Box<dyn ExploitObjective>> = vec![
        Box::new(GenericProfitObjective {
            rpc_url: args.rpc_url.clone(),
            chain_id: args.chain_id,
        }),
        Box::new(OracleSpotObjective {
            rpc_url: args.rpc_url.clone(),
            chain_id: args.chain_id,
            min_discrepancy_bps: 250,
            oracle_sanity_width_bps: 80,
        }),
    ];

    let findings = run_objectives_parallel(objectives, &bytecode, Some(target_context))
        .await
        .context("parallel objective runner failed")?;
    if args.json {
        let payload = serde_json::json!({
            "target": format!("{:#x}", args.target),
            "chain_id": args.chain_id,
            "block_number": args.block_number,
            "findings": findings.iter().map(|(objective, params)| {
                serde_json::json!({
                    "objective": objective,
                    "params": params.to_summary_json(),
                })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!(
            "[SHADOW_REPLAY] target={:?} block={} findings={}",
            args.target,
            args.block_number,
            findings.len()
        );
        for (name, params) in &findings {
            println!(
                "[SHADOW_REPLAY] objective='{}' steps={} loan={}",
                name,
                params.steps.len(),
                params.flash_loan_amount
            );
        }
    }

    if findings.is_empty() {
        return Err(anyhow::anyhow!(
            "no qualifying finding at target={:?} block={}",
            args.target,
            args.block_number
        ));
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
    }

    #[test]
    fn parse_args_from_iter_accepts_named_flags() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let args = parse_args_from_iter([
            "--rpc-url",
            "https://rpc.example",
            "--chain-id",
            "8453",
            "--address",
            "0x1111111111111111111111111111111111111111",
            "--block-number",
            "1024",
        ])
        .expect("parse");

        assert_eq!(
            args,
            Args {
                rpc_url: "https://rpc.example".to_string(),
                chain_id: 8453,
                target: Address::from([0x11; 20]),
                block_number: 1024,
                json: false,
            }
        );
    }

    #[test]
    fn parse_args_from_iter_uses_rpc_env_fallback() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();
        std::env::set_var("ETH_RPC_URL", "https://env-rpc.example");

        let args = parse_args_from_iter([
            "--chain-id",
            "1",
            "--address",
            "0x2222222222222222222222222222222222222222",
            "--block",
            "2048",
        ])
        .expect("parse");

        assert_eq!(args.rpc_url, "https://env-rpc.example");
        assert_eq!(args.target, Address::from([0x22; 20]));
        assert_eq!(args.block_number, 2048);
        assert!(!args.json);

        clear_env();
    }

    #[test]
    fn parse_args_from_iter_accepts_json_flag() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let args = parse_args_from_iter([
            "--rpc-url",
            "https://rpc.example",
            "--chain-id",
            "1",
            "--address",
            "0x3333333333333333333333333333333333333333",
            "--block-number",
            "4096",
            "--json",
        ])
        .expect("parse");

        assert_eq!(args.target, Address::from([0x33; 20]));
        assert!(args.json);
    }

    #[test]
    fn parse_args_from_iter_rejects_missing_block_number() {
        let _guard = env_lock().lock().expect("env lock");
        clear_env();

        let err = parse_args_from_iter([
            "--rpc-url",
            "https://rpc.example",
            "--chain-id",
            "1",
            "--address",
            "0x4444444444444444444444444444444444444444",
        ])
        .expect_err("missing block number should fail");

        assert!(err.to_string().contains("--block-number is required"));
    }
}
