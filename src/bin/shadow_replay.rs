use alloy::primitives::Address;
use anyhow::Context;
use dark_solver::fork_db::ForkDB;
use dark_solver::solver::objectives::{
    ExploitObjective, GenericProfitObjective, OracleSpotObjective,
};
use dark_solver::solver::runner::run_objectives_parallel;
use revm::DatabaseRef;
use std::str::FromStr;
use std::sync::Arc;

fn parse_arg<T: FromStr>(raw: &str, name: &str) -> anyhow::Result<T>
where
    <T as FromStr>::Err: std::fmt::Display,
{
    raw.parse::<T>()
        .map_err(|e| anyhow::anyhow!("invalid {name} '{raw}': {e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        return Err(anyhow::anyhow!(
            "usage: shadow_replay <rpc_url> <chain_id> <target_address> <block_number>"
        ));
    }

    let rpc_url = args[1].clone();
    let chain_id: u64 = parse_arg(&args[2], "chain_id")?;
    let target = Address::from_str(&args[3])?;
    let block_number: u64 = parse_arg(&args[4], "block_number")?;

    // Global pin for every ForkDB::new(...) call in this process.
    std::env::set_var("FORKDB_PIN_BLOCK_NUMBER", block_number.to_string());

    let fork_db = ForkDB::with_block_number(&rpc_url, block_number)?;
    let target_info = fork_db.basic_ref(target)?.ok_or_else(|| {
        anyhow::anyhow!("no account info for target {target:?} at block {block_number}")
    })?;
    let bytecode = target_info
        .code
        .map(|code| code.bytes())
        .ok_or_else(|| anyhow::anyhow!("target has no bytecode at block {block_number}"))?;
    if bytecode.is_empty() {
        return Err(anyhow::anyhow!(
            "target bytecode is empty at block {block_number}"
        ));
    }

    let target_context = Arc::new(dark_solver::solver::setup::hydrate_target_context(
        &rpc_url, chain_id, target, &bytecode, None,
    ));
    let objectives: Vec<Box<dyn ExploitObjective>> = vec![
        Box::new(GenericProfitObjective {
            rpc_url: rpc_url.clone(),
            chain_id,
        }),
        Box::new(OracleSpotObjective {
            rpc_url: rpc_url.clone(),
            chain_id,
            min_discrepancy_bps: 250,
            oracle_sanity_width_bps: 80,
        }),
    ];

    let findings = run_objectives_parallel(objectives, &bytecode, Some(target_context))
        .await
        .context("parallel objective runner failed")?;
    println!(
        "[SHADOW_REPLAY] target={:?} block={} findings={}",
        target,
        block_number,
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

    if findings.is_empty() {
        return Err(anyhow::anyhow!(
            "no qualifying finding at target={target:?} block={block_number}"
        ));
    }

    Ok(())
}
