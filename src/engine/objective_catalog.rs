use alloy::primitives::U256;
use std::env;

#[derive(Clone, Copy, Debug)]
pub struct ObjectiveScheduleHints {
    pub allow_deep: bool,
}

impl ObjectiveScheduleHints {
    pub fn permissive() -> Self {
        Self { allow_deep: true }
    }
}

pub fn build_objectives_with_hints(
    solver_rpc: String,
    chain_id: u64,
    hints: ObjectiveScheduleHints,
) -> Vec<Box<dyn crate::engine::objectives::ExploitObjective>> {
    let fast_chain = crate::config::chains::ChainConfig::get(chain_id).block_time_ms <= 2_500;
    let prng_max_modulo = if fast_chain { 2_048 } else { 10_000 };
    let max_timestamp_drift_seconds = if fast_chain { 8 } else { 15 };
    let objective_deep_scan_env = parse_bool_env("OBJECTIVE_DEEP_SCAN").unwrap_or(!fast_chain);
    let objective_deep_scan = objective_deep_scan_env && hints.allow_deep;

    if objective_deep_scan {
        tracing::info!(
            "[OBJECTIVES] Deep Scan ENABLED (Depth: 10). Searching for complex vectors..."
        );
    } else {
        tracing::info!("[OBJECTIVES] Deep Scan DISABLED.");
    }

    let default_spread = 35;
    let atomic_arb_min_spread_bps =
        parse_u64_env("ATOMIC_ARBITRAGE_MIN_SPREAD_BPS").unwrap_or(default_spread);

    let mut objectives: Vec<Box<dyn crate::engine::objectives::ExploitObjective>> = vec![
        Box::new(crate::engine::objectives::GenericProfitObjective {
            rpc_url: solver_rpc.clone(),
            chain_id,
        }),
        Box::new(crate::engine::objectives::AtomicArbitrageObjective {
            rpc_url: solver_rpc.clone(),
            min_spread_bps: atomic_arb_min_spread_bps.max(1),
        }),
        Box::new(crate::engine::objectives::AmmPriceImpactObjective {
            rpc_url: solver_rpc.clone(),
            min_price_impact_bps: 150,
            fee_pips: 3_000,
        }),
        Box::new(crate::engine::objectives::PsmDrainingObjective {
            rpc_url: solver_rpc.clone(),
            min_gain_bps: 50,
        }),
        Box::new(crate::engine::objectives::CollateralFactorLtvLagObjective {
            rpc_url: solver_rpc.clone(),
            collateral_factor_bps: 9000,
            min_pre_ltv_bps: 8700,
            shock_drop_bps: 5000,
        }),
        Box::new(crate::engine::objectives::TwapOracleManipulationObjective {
            rpc_url: solver_rpc.clone(),
            chain_id,
        }),
        Box::new(crate::engine::objectives::LiquidationSpiralObjective {
            rpc_url: solver_rpc.clone(),
            min_drop_bps: 500,
        }),
        Box::new(crate::engine::objectives::GovernanceExploitObjective {
            rpc_url: solver_rpc.clone(),
            min_quorum_threshold: 1,
            max_quorum_threshold: if fast_chain {
                10u64.pow(10)
            } else {
                10u64.pow(12)
            },
        }),
        Box::new(crate::engine::objectives::WeakPrngObjective {
            rpc_url: solver_rpc.clone(),
            max_timestamp_drift_seconds,
            min_modulo: 2,
            max_modulo: prng_max_modulo,
        }),
        Box::new(
            crate::engine::objectives::InterestRateModelGamingObjective {
                rpc_url: solver_rpc.clone(),
                min_rate_drop_bps: 4000,
            },
        ),
        Box::new(crate::engine::objectives::ReadOnlyReentrancyObjective {
            rpc_url: solver_rpc.clone(),
            min_price_drift_bps: 50,
        }),
        Box::new(
            crate::engine::objectives::DelegateCallStorageClashObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(crate::engine::objectives::VaultInflationObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::ShareRoundingGriefingObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::CompositeRiskSynthesisObjective {
            rpc_url: solver_rpc.clone(),
            chain_id,
        }),
    ];

    if objective_deep_scan {
        objectives.extend(build_deep_objectives_internal(
            solver_rpc.clone(),
            chain_id,
            fast_chain,
            prng_max_modulo,
            max_timestamp_drift_seconds,
        ));
    }

    let allow_filters = parse_csv_env("OBJECTIVE_ALLOWLIST");
    if !allow_filters.is_empty() {
        objectives.retain(|objective| name_matches_any(objective.name(), &allow_filters));
    }

    let deny_filters = parse_csv_env("OBJECTIVE_DENYLIST");
    if !deny_filters.is_empty() {
        objectives.retain(|objective| !name_matches_any(objective.name(), &deny_filters));
    }

    let default_cap = default_objective_cap(chain_id);
    let objective_cap = parse_usize_env("OBJECTIVE_MAX_PER_TARGET").unwrap_or(default_cap);
    if objective_cap > 0 && objectives.len() > objective_cap {
        objectives.truncate(objective_cap);
    }

    objectives
}

pub fn build_objectives(
    solver_rpc: String,
    chain_id: u64,
) -> Vec<Box<dyn crate::engine::objectives::ExploitObjective>> {
    build_objectives_with_hints(solver_rpc, chain_id, ObjectiveScheduleHints::permissive())
}

pub fn build_background_deep_objectives(
    solver_rpc: String,
    chain_id: u64,
) -> Vec<Box<dyn crate::engine::objectives::ExploitObjective>> {
    let fast_chain = crate::config::chains::ChainConfig::get(chain_id).block_time_ms <= 2_500;
    let prng_max_modulo = if fast_chain { 2_048 } else { 10_000 };
    let max_timestamp_drift_seconds = if fast_chain { 8 } else { 15 };
    // Deep scan in background is safe for fast chains because it is decoupled from the 1800ms
    // primary loop; operator can disable via OBJECTIVE_DEEP_SCAN=false.
    let objective_deep_scan_env = parse_bool_env("OBJECTIVE_DEEP_SCAN").unwrap_or(true);
    if !objective_deep_scan_env {
        return Vec::new();
    }

    let mut objectives = build_deep_objectives_internal(
        solver_rpc,
        chain_id,
        fast_chain,
        prng_max_modulo,
        max_timestamp_drift_seconds,
    );
    let allow_filters = parse_csv_env("OBJECTIVE_ALLOWLIST");
    if !allow_filters.is_empty() {
        objectives.retain(|objective| name_matches_any(objective.name(), &allow_filters));
    }

    let deny_filters = parse_csv_env("OBJECTIVE_DENYLIST");
    if !deny_filters.is_empty() {
        objectives.retain(|objective| !name_matches_any(objective.name(), &deny_filters));
    }

    objectives
}

fn build_deep_objectives_internal(
    solver_rpc: String,
    chain_id: u64,
    fast_chain: bool,
    prng_max_modulo: u64,
    max_timestamp_drift_seconds: u64,
) -> Vec<Box<dyn crate::engine::objectives::ExploitObjective>> {
    vec![
        Box::new(crate::engine::objectives::DeepInvariantAnalysisObjective {
            rpc_url: solver_rpc.clone(),
            chain_id,
        }),
        Box::new(crate::engine::objectives::ReentrancyObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::AtomicArbitrageObjective {
            rpc_url: solver_rpc.clone(),
            min_spread_bps: parse_u64_env("ATOMIC_ARBITRAGE_MIN_SPREAD_BPS").unwrap_or(35),
        }),
        Box::new(crate::engine::objectives::AmmPriceImpactObjective {
            rpc_url: solver_rpc.clone(),
            min_price_impact_bps: 150,
            fee_pips: 3_000,
        }),
        Box::new(crate::engine::objectives::PsmDrainingObjective {
            rpc_url: solver_rpc.clone(),
            min_gain_bps: 50,
        }),
        Box::new(crate::engine::objectives::ReadOnlyReentrancyObjective {
            rpc_url: solver_rpc.clone(),
            min_price_drift_bps: 50,
        }),
        Box::new(
            crate::engine::objectives::DelegateCallStorageClashObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(crate::engine::objectives::VaultInflationObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::ShareRoundingGriefingObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::CollateralFactorLtvLagObjective {
            rpc_url: solver_rpc.clone(),
            collateral_factor_bps: 9000,
            min_pre_ltv_bps: 8700,
            shock_drop_bps: 5000,
        }),
        Box::new(crate::engine::objectives::RedemptionArbitrageObjective {
            rpc_url: solver_rpc.clone(),
            min_gain_bps: 50,
        }),
        Box::new(crate::engine::objectives::DustBadDebtCreationObjective {
            rpc_url: solver_rpc.clone(),
            max_dust_debt: U256::from(10u64).pow(U256::from(19u64)),
            min_position_count: 1000,
            liquidation_bonus_bps: 800,
        }),
        Box::new(crate::engine::objectives::WeakPrngObjective {
            rpc_url: solver_rpc.clone(),
            max_timestamp_drift_seconds,
            min_modulo: 2,
            max_modulo: prng_max_modulo,
        }),
        Box::new(crate::engine::objectives::CommitRevealBypassObjective {
            rpc_url: solver_rpc.clone(),
            max_timestamp_drift_seconds,
            min_modulo: 2,
            max_modulo: prng_max_modulo,
        }),
        Box::new(
            crate::engine::objectives::GamblingContractScannerObjective {
                rpc_url: solver_rpc.clone(),
                max_timestamp_drift_seconds,
                min_modulo: 2,
                max_modulo: prng_max_modulo,
            },
        ),
        Box::new(
            crate::engine::objectives::ChainlinkVrfTimingAttackObjective {
                rpc_url: solver_rpc.clone(),
                min_modulo: 2,
                max_modulo: prng_max_modulo,
            },
        ),
        Box::new(crate::engine::objectives::GovernanceExploitObjective {
            rpc_url: solver_rpc.clone(),
            min_quorum_threshold: 1,
            max_quorum_threshold: if fast_chain {
                10u64.pow(10)
            } else {
                10u64.pow(12)
            },
        }),
        Box::new(crate::engine::objectives::TimelockExpirySnipingObjective {
            rpc_url: solver_rpc.clone(),
            max_eta_horizon_seconds: if fast_chain { 3_600 } else { 172_800 },
        }),
        Box::new(crate::engine::objectives::QuorumManipulationObjective {
            rpc_url: solver_rpc.clone(),
            quorum_ratio_bps: 2_000,
            min_mint_amount: 1,
            max_mint_amount: if fast_chain {
                10u64.pow(10)
            } else {
                10u64.pow(12)
            },
        }),
        Box::new(crate::engine::objectives::DelegateeHijackObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(
            crate::engine::objectives::Erc721CallbackReentrancyObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(
            crate::engine::objectives::Erc1155CallbackReentrancyObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(
            crate::engine::objectives::Erc721MintCallbackDrainObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(crate::engine::objectives::Erc721ApprovalHijackObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(
            crate::engine::objectives::ReadOnlyReentrancyScannerObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(crate::engine::objectives::Groth16VerifierAuditObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(
            crate::engine::objectives::L2NativeBridgeArbitrageObjective {
                rpc_url: solver_rpc.clone(),
                chain_id,
            },
        ),
        Box::new(
            crate::engine::objectives::ProxyImplementationLogicLagObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(crate::engine::objectives::SymbolicFuzzingObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::DifferentialConstraintObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(crate::engine::objectives::StateTransitionCycleObjective {
            rpc_url: solver_rpc.clone(),
        }),
        Box::new(
            crate::engine::objectives::TaintFlowStorageCorruptionObjective {
                rpc_url: solver_rpc.clone(),
            },
        ),
        Box::new(crate::engine::objectives::PolynomialInvariantObjective {
            rpc_url: solver_rpc.clone(),
        }),
    ]
}

fn parse_bool_env(key: &str) -> Option<bool> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .and_then(|normalized| match normalized.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn parse_usize_env(key: &str) -> Option<usize> {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
}

fn parse_u64_env(key: &str) -> Option<u64> {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn parse_csv_env(key: &str) -> Vec<String> {
    env::var(key)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| item.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn name_matches_any(name: &str, filters: &[String]) -> bool {
    let normalized_name = name.to_ascii_lowercase();
    filters
        .iter()
        .any(|filter| normalized_name.contains(filter.as_str()))
}

fn default_objective_cap(chain_id: u64) -> usize {
    let block_time_ms = crate::config::chains::ChainConfig::get(chain_id).block_time_ms;
    if block_time_ms <= 2_500 {
        14
    } else if block_time_ms <= 5_000 {
        24
    } else {
        usize::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::name_matches_any;

    #[test]
    fn test_name_matches_any_is_case_insensitive_substring() {
        let filters = vec!["oracle".to_string(), "reentrancy".to_string()];
        assert!(name_matches_any("Oracle Spot Manipulation", &filters));
        assert!(name_matches_any("READ-ONLY REENTRANCY", &filters));
        assert!(!name_matches_any("Governance Quorum", &filters));
    }
}
