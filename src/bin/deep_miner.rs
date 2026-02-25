use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{anyhow, Context, Result};
use dark_solver::engine::objective_catalog::build_objectives;
use dark_solver::engine::runner::run_objectives_parallel_detailed;
use dark_solver::engine::setup::hydrate_target_context;
use dark_solver::utils::rpc::RobustRpc;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug)]
struct Args {
    file_path: String,
    rpc_url: String,
    chain_id: Option<u64>,
    strict: bool,
    timeout_ms: Option<u64>,
    report_path: Option<PathBuf>,
    replay: bool,
    full: bool,
}

fn print_usage() {
    eprintln!(
        "usage: deep_miner --file <path> [--rpc-url <url>] [--chain-id <id>] [--report <path>]\n\
         options:\n\
           --strict           fail closed if any objective times out/panics\n\
           --timeout-ms <ms>  total per-target objective-battery timeout\n\
           --no-replay        skip fork replay validation for SAT findings\n\
           --full             force OBJECTIVE_DEEP_SCAN=true and OBJECTIVE_MAX_PER_TARGET=0\n\
         env fallback: ETH_RPC_URL or RPC_URL"
    );
}

fn parse_args() -> Result<Args> {
    let mut file_path: Option<String> = None;
    let mut rpc_url = std::env::var("ETH_RPC_URL")
        .ok()
        .or_else(|| std::env::var("RPC_URL").ok());
    let mut chain_id: Option<u64> = None;
    let mut strict = false;
    let mut timeout_ms: Option<u64> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut replay = true;
    let mut full = true;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--file" | "-f" => {
                file_path = Some(
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
            "--strict" => strict = true,
            "--timeout-ms" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                timeout_ms = Some(
                    raw.parse::<u64>()
                        .map_err(|e| anyhow!("invalid timeout ms '{raw}': {e}"))?,
                );
            }
            "--report" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for {arg}"))?;
                report_path = Some(PathBuf::from(raw));
            }
            "--no-replay" => replay = false,
            "--full" => full = true,
            "--no-full" => full = false,
            other => return Err(anyhow!("unknown argument '{other}'")),
        }
    }

    let file_path = file_path.ok_or_else(|| anyhow!("--file is required"))?;
    let rpc_url =
        rpc_url.ok_or_else(|| anyhow!("--rpc-url (or ETH_RPC_URL/RPC_URL env) is required"))?;

    Ok(Args {
        file_path,
        rpc_url,
        chain_id,
        strict,
        timeout_ms,
        report_path,
        replay,
        full,
    })
}

#[derive(Debug, Serialize, Clone)]
struct ObjectiveRecordReport {
    objective: String,
    elapsed_ms: u128,
    status: String,
}

#[derive(Debug, Serialize, Clone)]
struct FindingReplayReport {
    success: bool,
    profitable: bool,
    estimated_gas: u64,
    initial_value_wei: String,
    final_value_wei: String,
    gas_cost_wei: String,
    priced_tokens: usize,
    unpriced_tokens: usize,
    stale_priced_tokens: usize,
    error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct FindingReport {
    objective: String,
    expected_profit_wei: Option<String>,
    steps: usize,
    flash_loan_amount_wei: String,
    replay: Option<FindingReplayReport>,
}

#[derive(Debug, Serialize)]
struct TargetReport {
    chain_id: u64,
    target: String,
    bytecode_len: usize,
    objectives_total: usize,
    records: Vec<ObjectiveRecordReport>,
    findings: Vec<FindingReport>,
    sat_findings: usize,
    unsat_objectives: usize,
    timed_out_objectives: usize,
    panicked_objectives: usize,
    strict_incomplete: bool,
    wall_ms: u128,
    error: Option<String>,
}

fn status_to_string(status: &dark_solver::solver::runner::ObjectiveRunStatus) -> String {
    match status {
        dark_solver::solver::runner::ObjectiveRunStatus::Sat => "SAT".to_string(),
        dark_solver::solver::runner::ObjectiveRunStatus::Unsat => "UNSAT".to_string(),
        dark_solver::solver::runner::ObjectiveRunStatus::Timeout => "TIMEOUT".to_string(),
        dark_solver::solver::runner::ObjectiveRunStatus::Panic(msg) => format!("PANIC: {msg}"),
    }
}

fn default_report_path() -> PathBuf {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    PathBuf::from(format!("artifacts/reports/deep_miner_{epoch}.jsonl"))
}

async fn process_target(
    args: &Args,
    chain_id: u64,
    hydration_pool: &dark_solver::utils::rpc::HydrationProviderPool,
    address: Address,
) -> Result<TargetReport> {
    let wall_started = std::time::Instant::now();
    let bytecode = RobustRpc::get_code_with_hydration_pool_retry(hydration_pool, address, 3)
        .await
        .context("failed to fetch target bytecode")?;

    if bytecode.is_empty() {
        return Ok(TargetReport {
            chain_id,
            target: format!("{address:#x}"),
            bytecode_len: 0,
            objectives_total: 0,
            records: Vec::new(),
            findings: Vec::new(),
            sat_findings: 0,
            unsat_objectives: 0,
            timed_out_objectives: 0,
            panicked_objectives: 0,
            strict_incomplete: false,
            wall_ms: wall_started.elapsed().as_millis(),
            error: None,
        });
    }

    let target_context = Arc::new(hydrate_target_context(
        &args.rpc_url,
        chain_id,
        Address::from_slice(address.as_slice()),
        &bytecode,
        None,
    ));

    let objectives = build_objectives(args.rpc_url.clone(), chain_id);
    let objectives_total = objectives.len();
    let (records, findings) = run_objectives_parallel_detailed(
        objectives,
        &bytecode,
        Some(target_context),
        args.timeout_ms,
    )
    .await
    .context("parallel objective runner failed")?;

    let mut unsat_objectives = 0usize;
    let mut timed_out_objectives = 0usize;
    let mut panicked_objectives = 0usize;
    let mut record_reports = Vec::with_capacity(records.len());
    for rec in &records {
        let status = status_to_string(&rec.status);
        if status == "UNSAT" {
            unsat_objectives += 1;
        } else if status == "TIMEOUT" {
            timed_out_objectives += 1;
        } else if status.starts_with("PANIC:") {
            panicked_objectives += 1;
        }
        record_reports.push(ObjectiveRecordReport {
            objective: rec.objective.clone(),
            elapsed_ms: rec.elapsed_ms,
            status,
        });
    }

    let mut finding_reports = Vec::with_capacity(findings.len());
    for (obj_name, params) in findings.iter() {
        let replay_report = if args.replay {
            let attacker_revm = dark_solver::solver::setup::ATTACKER;
            let attacker = alloy::primitives::Address::from_slice(attacker_revm.as_slice());
            let shadow = dark_solver::executor::verifier::replay_path(
                &args.rpc_url,
                chain_id,
                attacker,
                params,
            );
            Some(FindingReplayReport {
                success: shadow.success,
                profitable: shadow.profitable,
                estimated_gas: shadow.estimated_gas,
                initial_value_wei: shadow.initial_value_wei.to_string(),
                final_value_wei: shadow.final_value_wei.to_string(),
                gas_cost_wei: shadow.gas_cost_wei.to_string(),
                priced_tokens: shadow.priced_tokens,
                unpriced_tokens: shadow.unpriced_tokens,
                stale_priced_tokens: shadow.stale_priced_tokens,
                error: shadow.error,
            })
        } else {
            None
        };

        finding_reports.push(FindingReport {
            objective: obj_name.clone(),
            expected_profit_wei: params.expected_profit.map(|v| v.to_string()),
            steps: params.steps.len(),
            flash_loan_amount_wei: params.flash_loan_amount.to_string(),
            replay: replay_report,
        });
    }

    let strict_incomplete = timed_out_objectives > 0 || panicked_objectives > 0;

    Ok(TargetReport {
        chain_id,
        target: format!("{address:#x}"),
        bytecode_len: bytecode.len(),
        objectives_total,
        records: record_reports,
        sat_findings: finding_reports.len(),
        findings: finding_reports,
        unsat_objectives,
        timed_out_objectives,
        panicked_objectives,
        strict_incomplete,
        wall_ms: wall_started.elapsed().as_millis(),
        error: None,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args().inspect_err(|_| print_usage())?;

    if args.full {
        // Audit tooling default: do not cap the catalog, and always include deep objectives.
        // This keeps "coverage semantics" operator-friendly without forcing env tuning.
        std::env::set_var("OBJECTIVE_DEEP_SCAN", "true");
        std::env::set_var("OBJECTIVE_MAX_PER_TARGET", "0");
    }

    // Auto-detect chain ID once
    let chain_id = match args.chain_id {
        Some(id) => id,
        None => {
            let provider = ProviderBuilder::new().on_http(args.rpc_url.parse()?);
            tokio::time::timeout(
                std::time::Duration::from_millis(5_000), // Relaxed checking timeout
                provider.get_chain_id(),
            )
            .await
            .context("RPC chain_id fetch timed out")??
        }
    };

    println!("[MINER] chain_id={}", chain_id);
    let (hydration_pool, _) =
        dark_solver::utils::rpc::build_hydration_provider_pool(&args.rpc_url)?;

    let report_path = args.report_path.clone().unwrap_or_else(default_report_path);
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create report directory")?;
    }
    let mut report_file = File::create(&report_path).context("failed to create report file")?;
    println!("[MINER] report={}", report_path.display());

    // Read targets
    let file = File::open(&args.file_path).context("failed to open target file")?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    println!(
        "[MINER] Should process {} targets from {}",
        lines.len(),
        args.file_path
    );

    let mut any_incomplete = false;
    let mut processed = 0usize;
    for line in lines.iter() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let address = match Address::from_str(trimmed) {
            Ok(a) => a,
            Err(_) => {
                eprintln!("[WARN] skipping invalid address: {}", trimmed);
                continue;
            }
        };

        processed += 1;
        println!(
            "\n[MINER] Processing target {}/{} : {:?}",
            processed,
            lines.len(),
            address
        );

        let mut report = match process_target(&args, chain_id, &hydration_pool, address).await {
            Ok(report) => report,
            Err(e) => {
                any_incomplete = true;
                TargetReport {
                    chain_id,
                    target: format!("{address:#x}"),
                    bytecode_len: 0,
                    objectives_total: 0,
                    records: Vec::new(),
                    findings: Vec::new(),
                    sat_findings: 0,
                    unsat_objectives: 0,
                    timed_out_objectives: 0,
                    panicked_objectives: 0,
                    strict_incomplete: true,
                    wall_ms: 0,
                    error: Some(e.to_string()),
                }
            }
        };

        if report.bytecode_len == 0 {
            println!("  -> [SKIP] Empty bytecode (EOA?)");
        } else if report.sat_findings == 0 {
            println!(
                "  -> [CLEAN] No SAT findings ({} objectives UNSAT).",
                report.unsat_objectives
            );
        } else {
            println!("  -> [FOUND] {} SAT findings.", report.sat_findings);
            for f in &report.findings {
                if let Some(replay) = &f.replay {
                    println!(
                        "     - {} | replay: success={} profitable={} gas={}",
                        f.objective, replay.success, replay.profitable, replay.estimated_gas
                    );
                } else {
                    println!("     - {} | replay: skipped", f.objective);
                }
            }
        }

        if args.strict && report.strict_incomplete {
            any_incomplete = true;
        }

        if report.wall_ms == 0 {
            // Preserve a minimal wall-time marker even for error reports.
            report.wall_ms = 0;
        }

        let line = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
        writeln!(report_file, "{line}").context("failed to write report line")?;
    }

    if args.strict && any_incomplete {
        return Err(anyhow!(
            "strict mode: one or more targets failed/incomplete (see report)"
        ));
    }

    println!("[MINER] done. report={}", report_path.display());
    Ok(())
}
