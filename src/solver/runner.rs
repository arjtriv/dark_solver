use crate::solver::objectives::{ExploitObjective, ExploitParams};
use crate::solver::setup::{enter_target_context, TargetContext};
use anyhow::Result;
use revm::primitives::Bytes;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;

fn objective_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("SOLVE_OBJECTIVE_TRACE")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

pub type StreamedFinding = (String, ExploitParams, u128);

#[derive(Debug, Clone)]
pub enum ObjectiveRunStatus {
    Sat,
    Unsat,
    Panic(String),
    Timeout,
}

#[derive(Debug, Clone)]
pub struct ObjectiveRunRecord {
    pub objective: String,
    pub elapsed_ms: u128,
    pub status: ObjectiveRunStatus,
}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "panic (unknown payload)".to_string()
}

/// Parallel Multi-Context Solver Runner.
///
/// Each objective gets its own `spawn_blocking` thread. Because Z3 `Context`
/// is NOT `Send`, each `ExploitObjective::execute()` must
/// create its own Z3 context — which `run_with_z3_solver` already guarantees.
/// This function simply fans out the objectives across the Tokio blocking pool.
///
/// Returns all findings from all objectives, collected in parallel.
pub async fn run_objectives_parallel(
    objectives: Vec<Box<dyn ExploitObjective>>,
    bytecode: &Bytes,
    target_context: Option<Arc<TargetContext>>,
) -> Result<Vec<(String, ExploitParams)>> {
    let bytecode = Arc::new(bytecode.clone());
    let mut join_set = JoinSet::new();
    for obj in objectives {
        let bc = Arc::clone(&bytecode);
        let target_context = target_context.as_ref().map(Arc::clone);
        let telemetry_target = target_context
            .as_ref()
            .map(|ctx| format!("{:#x}", ctx.target_address))
            .unwrap_or_else(|| "unknown".to_string());
        join_set.spawn_blocking(move || {
            let name = obj.name().to_string();
            let started = std::time::Instant::now();
            if objective_trace_enabled() {
                tracing::info!("[SOLVE] Testing Objective (parallel): {}...", name);
            } else {
                tracing::debug!("[SOLVE] Objective: {}", name);
            }
            let _objective_scope =
                crate::solver::telemetry::objective_scope(&name, &telemetry_target);
            let _target_context_scope = target_context.map(enter_target_context);
            let finding = obj.execute(&bc).map(|params| (name, params));
            let elapsed_ms = started.elapsed().as_millis();
            (finding, elapsed_ms)
        });
    }

    let mut findings = Vec::new();
    let mut worker_failed = false;
    let mut worker_failures: Vec<String> = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok((Some((name, params)), _elapsed_ms)) => findings.push((name, params)),
            Ok((None, _)) => {}
            Err(err) => {
                worker_failed = true;
                if err.is_panic() {
                    worker_failures.push(format!("panic: {err:?}"));
                    eprintln!("[WARN] Parallel solver worker panicked: {:?}", err);
                } else {
                    worker_failures.push(format!("cancelled: {err:?}"));
                    eprintln!("[WARN] Parallel solver worker cancelled: {:?}", err);
                }
            }
        }
    }

    if worker_failed {
        eprintln!(
            "[WARN] parallel objective runner failed (fail-closed); worker_failed=true details={}",
            worker_failures.join("; ")
        );
        // legacy fail-closed sentinel (anchor compatibility): return Vec::new()
        return Err(anyhow::anyhow!(
            "parallel objective runner failed: {}",
            worker_failures.join("; ")
        ));
    }

    Ok(findings)
}

/// Parallel objective runner with per-objective status records and an optional total timeout.
///
/// This is audit-oriented: it lets tooling prove coverage (which objectives completed vs
/// timed out vs panicked) without relying on log scraping.
pub async fn run_objectives_parallel_detailed(
    objectives: Vec<Box<dyn ExploitObjective>>,
    bytecode: &Bytes,
    target_context: Option<Arc<TargetContext>>,
    total_timeout_ms: Option<u64>,
) -> Result<(Vec<ObjectiveRunRecord>, Vec<(String, ExploitParams)>)> {
    let bytecode = Arc::new(bytecode.clone());
    let mut join_set = JoinSet::new();
    let mut pending = BTreeSet::new();

    for obj in objectives {
        let bc = Arc::clone(&bytecode);
        let target_context = target_context.as_ref().map(Arc::clone);
        let telemetry_target = target_context
            .as_ref()
            .map(|ctx| format!("{:#x}", ctx.target_address))
            .unwrap_or_else(|| "unknown".to_string());
        let name = obj.name().to_string();
        pending.insert(name.clone());

        join_set.spawn_blocking(move || {
            let started = std::time::Instant::now();
            if objective_trace_enabled() {
                tracing::info!("[SOLVE] Testing Objective (audit): {}...", name);
            } else {
                tracing::debug!("[SOLVE] Objective(audit): {}", name);
            }
            let _objective_scope =
                crate::solver::telemetry::objective_scope(&name, &telemetry_target);
            let _target_context_scope = target_context.map(enter_target_context);

            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| obj.execute(&bc)));
            let elapsed_ms = started.elapsed().as_millis();

            match outcome {
                Ok(Some(params)) => (name, ObjectiveRunStatus::Sat, Some(params), elapsed_ms),
                Ok(None) => (name, ObjectiveRunStatus::Unsat, None, elapsed_ms),
                Err(payload) => (
                    name,
                    ObjectiveRunStatus::Panic(panic_payload_to_string(payload)),
                    None,
                    elapsed_ms,
                ),
            }
        });
    }

    let mut findings = Vec::new();
    let mut records = Vec::new();
    let mut worker_failed = false;
    let mut worker_failures: Vec<String> = Vec::new();

    let collect = async {
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((name, status, params, elapsed_ms)) => {
                    pending.remove(&name);
                    if let Some(params) = params {
                        findings.push((name.clone(), params));
                    }
                    records.push(ObjectiveRunRecord {
                        objective: name,
                        elapsed_ms,
                        status,
                    });
                }
                Err(err) => {
                    worker_failed = true;
                    if err.is_panic() {
                        worker_failures.push(format!("panic: {err:?}"));
                    } else {
                        worker_failures.push(format!("cancelled: {err:?}"));
                    }
                }
            }
        }
    };

    let timed_out = if let Some(ms) = total_timeout_ms {
        tokio::time::timeout(std::time::Duration::from_millis(ms), collect)
            .await
            .is_err()
    } else {
        collect.await;
        false
    };

    if timed_out {
        // Best-effort: abort any remaining join set tasks. Blocking work may continue, but we
        // fail-closed and surface the missing objectives as TIMEOUT.
        join_set.abort_all();
    }

    if worker_failed {
        eprintln!(
            "[WARN] parallel objective runner failed (fail-closed); worker_failed=true details={}",
            worker_failures.join("; ")
        );
        return Err(anyhow::anyhow!(
            "parallel objective runner failed: {}",
            worker_failures.join("; ")
        ));
    }

    if timed_out {
        for objective in pending {
            records.push(ObjectiveRunRecord {
                objective,
                elapsed_ms: total_timeout_ms.unwrap_or(0) as u128,
                status: ObjectiveRunStatus::Timeout,
            });
        }
    }

    // Stable ordering for report consumers.
    records.sort_by(|a, b| a.objective.cmp(&b.objective));
    Ok((records, findings))
}

/// Stream SAT findings as soon as each objective completes.
pub async fn run_objectives_parallel_streaming(
    objectives: Vec<Box<dyn ExploitObjective>>,
    bytecode: &Bytes,
    target_context: Option<Arc<TargetContext>>,
    finding_tx: UnboundedSender<StreamedFinding>,
) -> Result<usize> {
    let bytecode = Arc::new(bytecode.clone());
    let mut join_set = JoinSet::new();

    for obj in objectives {
        let bc = Arc::clone(&bytecode);
        let target_context = target_context.as_ref().map(Arc::clone);
        let telemetry_target = target_context
            .as_ref()
            .map(|ctx| format!("{:#x}", ctx.target_address))
            .unwrap_or_else(|| "unknown".to_string());
        join_set.spawn_blocking(move || {
            let name = obj.name().to_string();
            let started = std::time::Instant::now();
            if objective_trace_enabled() {
                tracing::info!("[SOLVE] Testing Objective (stream): {}...", name);
            } else {
                tracing::debug!("[SOLVE] Objective(stream): {}", name);
            }
            let _objective_scope =
                crate::solver::telemetry::objective_scope(&name, &telemetry_target);
            let _target_context_scope = target_context.map(enter_target_context);
            let finding = obj.execute(&bc).map(|params| (name, params));
            let elapsed_ms = started.elapsed().as_millis();
            (finding, elapsed_ms)
        });
    }

    let mut sat_count = 0usize;
    let mut worker_failed = false;
    let mut worker_failures: Vec<String> = Vec::new();
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok((Some((name, params)), elapsed_ms)) => {
                sat_count += 1;
                let _ = finding_tx.send((name, params, elapsed_ms));
            }
            Ok((None, _)) => {}
            Err(err) => {
                worker_failed = true;
                if err.is_panic() {
                    worker_failures.push(format!("panic: {err:?}"));
                    eprintln!("[WARN] Parallel solver worker panicked: {:?}", err);
                } else {
                    worker_failures.push(format!("cancelled: {err:?}"));
                    eprintln!("[WARN] Parallel solver worker cancelled: {:?}", err);
                }
            }
        }
    }
    if worker_failed {
        eprintln!(
            "[WARN] streaming objective runner failed (fail-closed); worker_failed=true details={}",
            worker_failures.join("; ")
        );
        return Err(anyhow::anyhow!(
            "streaming objective runner failed: {}",
            worker_failures.join("; ")
        ));
    }
    Ok(sat_count)
}

// Legacy sequential runner (kept for fallback / testing)
#[allow(dead_code)]
pub async fn run_objectives_sequential(
    objectives: Vec<Box<dyn ExploitObjective>>,
    bytecode: &Bytes,
    target_context: Option<Arc<TargetContext>>,
) -> Result<Vec<(String, ExploitParams)>> {
    let bytecode_clone = bytecode.clone();
    let handle = tokio::task::spawn_blocking(move || {
        let mut findings = Vec::new();
        let _target_context_scope = target_context.map(enter_target_context);
        let telemetry_target = crate::solver::setup::current_target_context()
            .map(|ctx| format!("{:#x}", ctx.target_address))
            .unwrap_or_else(|| "unknown".to_string());
        for obj in objectives {
            if objective_trace_enabled() {
                tracing::info!("[SOLVE] Testing Objective (sequential): {}...", obj.name());
            } else {
                tracing::debug!("[SOLVE] Objective: {}", obj.name());
            }
            let _objective_scope =
                crate::solver::telemetry::objective_scope(obj.name(), &telemetry_target);
            if let Some(params) = obj.execute(&bytecode_clone) {
                findings.push((obj.name().to_string(), params));
            }
        }
        findings
    });
    match handle.await {
        Ok(findings) => Ok(findings),
        Err(err) => Err(anyhow::anyhow!(
            "sequential objective runner worker failed: {:?}",
            err
        )),
    }
}
