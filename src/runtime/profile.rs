use crate::config::chains::ChainConfig;
use crate::runtime::args::OperatorProfile;
use std::env;

#[derive(Debug, Clone)]
pub struct DynamicProfileReport {
    pub requested: OperatorProfile,
    pub effective: OperatorProfile,
    pub chain_id: u64,
    pub chain_name: String,
    pub fast_chain: bool,
    pub cpu_parallelism: usize,
    pub injected_defaults: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
struct ProfileTuning {
    submission_enabled: bool,
    deep_scan: bool,
    objective_max_per_target: usize,
    background_workers: usize,
    background_capacity: usize,
    concrete_fuzz_budget_ms: u64,
    jit_tuner_budget_ms: u64,
    proof_recheck_per_block: usize,
    proof_max_items: usize,
    contested_benchmark_enabled: bool,
}

fn parse_bool_env(key: &str) -> Option<bool> {
    env::var(key)
        .ok()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .and_then(|raw| match raw.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn parse_chain_id() -> u64 {
    env::var("CHAIN_ID")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(8453)
}

fn cpu_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .max(1)
}

fn resolve_auto_profile(
    fast_chain: bool,
    cpu_parallelism: usize,
    submission_mode_requested: bool,
) -> OperatorProfile {
    if submission_mode_requested {
        return OperatorProfile::Live;
    }
    if fast_chain && cpu_parallelism <= 4 {
        return OperatorProfile::Fast;
    }
    if cpu_parallelism >= 12 {
        return OperatorProfile::Deep;
    }
    OperatorProfile::Balanced
}

fn tuning_for_profile(profile: OperatorProfile, fast_chain: bool, cpu: usize) -> ProfileTuning {
    let worker_upper = cpu.clamp(1, 8);
    match profile {
        OperatorProfile::Auto => ProfileTuning {
            submission_enabled: false,
            deep_scan: true,
            objective_max_per_target: if fast_chain { 28 } else { 36 },
            background_workers: worker_upper.clamp(2, 4),
            background_capacity: 256,
            concrete_fuzz_budget_ms: 300,
            jit_tuner_budget_ms: 12,
            proof_recheck_per_block: 2,
            proof_max_items: 192,
            contested_benchmark_enabled: false,
        },
        OperatorProfile::Fast => ProfileTuning {
            submission_enabled: false,
            deep_scan: false,
            objective_max_per_target: if fast_chain { 18 } else { 24 },
            background_workers: worker_upper.min(2),
            background_capacity: 128,
            concrete_fuzz_budget_ms: 200,
            jit_tuner_budget_ms: 8,
            proof_recheck_per_block: 2,
            proof_max_items: 128,
            contested_benchmark_enabled: false,
        },
        OperatorProfile::Balanced => ProfileTuning {
            submission_enabled: false,
            deep_scan: true,
            objective_max_per_target: if fast_chain { 28 } else { 40 },
            background_workers: worker_upper.clamp(2, 4),
            background_capacity: 256,
            concrete_fuzz_budget_ms: 300,
            jit_tuner_budget_ms: 10,
            proof_recheck_per_block: 2,
            proof_max_items: 192,
            contested_benchmark_enabled: false,
        },
        OperatorProfile::Deep => ProfileTuning {
            submission_enabled: false,
            deep_scan: true,
            objective_max_per_target: if fast_chain { 40 } else { 64 },
            background_workers: worker_upper.clamp(4, 8),
            background_capacity: 512,
            concrete_fuzz_budget_ms: 450,
            jit_tuner_budget_ms: 20,
            proof_recheck_per_block: 3,
            proof_max_items: 256,
            contested_benchmark_enabled: false,
        },
        OperatorProfile::Live => ProfileTuning {
            submission_enabled: true,
            deep_scan: false,
            objective_max_per_target: if fast_chain { 20 } else { 28 },
            background_workers: worker_upper.clamp(2, 6),
            background_capacity: 256,
            concrete_fuzz_budget_ms: 250,
            jit_tuner_budget_ms: 8,
            proof_recheck_per_block: 2,
            proof_max_items: 160,
            contested_benchmark_enabled: true,
        },
    }
}

fn set_env_if_missing(key: &str, value: String, injected: &mut Vec<(String, String)>) {
    if env::var_os(key).is_none() {
        env::set_var(key, &value);
        injected.push((key.to_string(), value));
    }
}

pub fn apply_runtime_profile(requested: OperatorProfile) -> DynamicProfileReport {
    let chain_id = parse_chain_id();
    let chain = ChainConfig::get(chain_id);
    let fast_chain = chain.block_time_ms <= 2_500;
    let cpu_parallelism = cpu_parallelism();
    let submission_mode_requested = parse_bool_env("TX_SUBMISSION_ENABLED").unwrap_or(false);
    let effective = if matches!(requested, OperatorProfile::Auto) {
        resolve_auto_profile(fast_chain, cpu_parallelism, submission_mode_requested)
    } else {
        requested
    };
    let tuning = tuning_for_profile(effective, fast_chain, cpu_parallelism);
    let mut injected_defaults = Vec::new();

    set_env_if_missing(
        "DARK_OPERATOR_PROFILE_EFFECTIVE",
        effective.as_str().to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "TX_SUBMISSION_ENABLED",
        if tuning.submission_enabled {
            "true".to_string()
        } else {
            "false".to_string()
        },
        &mut injected_defaults,
    );
    set_env_if_missing(
        "OBJECTIVE_DEEP_SCAN",
        if tuning.deep_scan {
            "true".to_string()
        } else {
            "false".to_string()
        },
        &mut injected_defaults,
    );
    set_env_if_missing(
        "OBJECTIVE_MAX_PER_TARGET",
        tuning.objective_max_per_target.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "BACKGROUND_SOLVER_QUEUE_WORKERS",
        tuning.background_workers.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "BACKGROUND_SOLVER_QUEUE_CAPACITY",
        tuning.background_capacity.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "CONCRETE_FUZZ_BUDGET_MS",
        tuning.concrete_fuzz_budget_ms.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "JIT_TUNER_BUDGET_MS",
        tuning.jit_tuner_budget_ms.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "PROOF_PERSISTENCE_RECHECK_PER_BLOCK",
        tuning.proof_recheck_per_block.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "PROOF_PERSISTENCE_MAX_ITEMS",
        tuning.proof_max_items.to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "CONTESTED_BENCHMARK_ENABLED",
        if tuning.contested_benchmark_enabled {
            "true".to_string()
        } else {
            "false".to_string()
        },
        &mut injected_defaults,
    );
    set_env_if_missing(
        "RUNTIME_FAIL_CLOSED_ON_UNCERTAINTY",
        "true".to_string(),
        &mut injected_defaults,
    );

    DynamicProfileReport {
        requested,
        effective,
        chain_id,
        chain_name: chain.name,
        fast_chain,
        cpu_parallelism,
        injected_defaults,
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_runtime_profile, OperatorProfile};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_keys() {
        for key in [
            "CHAIN_ID",
            "TX_SUBMISSION_ENABLED",
            "OBJECTIVE_DEEP_SCAN",
            "OBJECTIVE_MAX_PER_TARGET",
            "BACKGROUND_SOLVER_QUEUE_WORKERS",
            "BACKGROUND_SOLVER_QUEUE_CAPACITY",
            "CONCRETE_FUZZ_BUDGET_MS",
            "JIT_TUNER_BUDGET_MS",
            "PROOF_PERSISTENCE_RECHECK_PER_BLOCK",
            "PROOF_PERSISTENCE_MAX_ITEMS",
            "CONTESTED_BENCHMARK_ENABLED",
            "RUNTIME_FAIL_CLOSED_ON_UNCERTAINTY",
            "DARK_OPERATOR_PROFILE_EFFECTIVE",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn auto_profile_resolves_and_injects_defaults() {
        let _guard = env_lock().lock().expect("env lock");
        clear_keys();
        std::env::set_var("CHAIN_ID", "8453");

        let report = apply_runtime_profile(OperatorProfile::Auto);
        assert!(!report.injected_defaults.is_empty());
        assert!(
            report.effective == OperatorProfile::Fast
                || report.effective == OperatorProfile::Balanced
                || report.effective == OperatorProfile::Deep
        );
        assert!(std::env::var("OBJECTIVE_MAX_PER_TARGET").is_ok());
        assert!(std::env::var("BACKGROUND_SOLVER_QUEUE_WORKERS").is_ok());

        clear_keys();
    }

    #[test]
    fn explicit_env_values_are_not_overridden() {
        let _guard = env_lock().lock().expect("env lock");
        clear_keys();
        std::env::set_var("CHAIN_ID", "8453");
        std::env::set_var("OBJECTIVE_MAX_PER_TARGET", "999");
        std::env::set_var("TX_SUBMISSION_ENABLED", "false");

        let report = apply_runtime_profile(OperatorProfile::Deep);
        let injected_keys: Vec<String> = report
            .injected_defaults
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert!(
            !injected_keys
                .iter()
                .any(|k| k == "OBJECTIVE_MAX_PER_TARGET"),
            "explicit OBJECTIVE_MAX_PER_TARGET should not be overwritten"
        );
        assert_eq!(
            std::env::var("OBJECTIVE_MAX_PER_TARGET").ok().as_deref(),
            Some("999")
        );

        clear_keys();
    }

    #[test]
    fn live_profile_defaults_submission_mode_when_missing() {
        let _guard = env_lock().lock().expect("env lock");
        clear_keys();
        std::env::set_var("CHAIN_ID", "8453");

        let report = apply_runtime_profile(OperatorProfile::Live);
        assert_eq!(report.effective, OperatorProfile::Live);
        assert_eq!(std::env::var("TX_SUBMISSION_ENABLED").ok().as_deref(), Some("true"));

        clear_keys();
    }
}
