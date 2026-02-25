use alloy::primitives::U256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncertaintyClass {
    RpcCooldown,
    DrawdownUnavailable,
    PerBlockLossUnavailable,
}

#[derive(Debug, Clone, Copy)]
pub struct ProfitWeightedExecutionPolicy {
    pub enabled: bool,
    /// Override fail-closed uncertainty gates only if `expected_profit / risk_budget >= roi_multiple`.
    pub roi_multiple: u64,
    pub risk_budget_wei: U256,
}

/// Pressure-optimized risk weighting: ignore generic global RPC cooldowns for high-capital targets.
pub fn should_override_rpc_cooldown_for_high_capital(
    enabled: bool,
    target_capital_eth_wei: Option<U256>,
    threshold_eth_wei: U256,
) -> bool {
    if !enabled {
        return false;
    }
    if threshold_eth_wei.is_zero() {
        return false;
    }
    let Some(capital) = target_capital_eth_wei else {
        return false;
    };
    capital >= threshold_eth_wei
}

impl ProfitWeightedExecutionPolicy {
    pub fn inactive() -> Self {
        Self {
            enabled: false,
            roi_multiple: 0,
            risk_budget_wei: U256::ZERO,
        }
    }

    pub fn is_active(&self) -> bool {
        self.enabled && self.roi_multiple > 0 && !self.risk_budget_wei.is_zero()
    }

    pub fn profit_to_risk_ratio_x_floor(&self, expected_profit_wei: U256) -> Option<U256> {
        if !self.is_active() {
            return None;
        }
        if expected_profit_wei.is_zero() {
            return Some(U256::ZERO);
        }
        Some(expected_profit_wei / self.risk_budget_wei)
    }

    pub fn should_override_fail_closed(
        &self,
        expected_profit_wei: Option<U256>,
        _uncertainty: UncertaintyClass,
    ) -> bool {
        let Some(expected_profit_wei) = expected_profit_wei else {
            return false;
        };
        let Some(ratio_x) = self.profit_to_risk_ratio_x_floor(expected_profit_wei) else {
            return false;
        };
        ratio_x >= U256::from(self.roi_multiple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profit_weighted_policy_inactive_never_overrides() {
        let policy = ProfitWeightedExecutionPolicy::inactive();
        assert!(!policy
            .should_override_fail_closed(Some(U256::from(1u64)), UncertaintyClass::RpcCooldown));
    }

    #[test]
    fn test_profit_weighted_policy_requires_ratio_multiple() {
        let policy = ProfitWeightedExecutionPolicy {
            enabled: true,
            roi_multiple: 10,
            risk_budget_wei: U256::from(100u64),
        };

        // 999 / 100 = 9 (floor) < 10
        assert!(!policy
            .should_override_fail_closed(Some(U256::from(999u64)), UncertaintyClass::RpcCooldown));

        // 1000 / 100 = 10 >= 10
        assert!(policy
            .should_override_fail_closed(Some(U256::from(1000u64)), UncertaintyClass::RpcCooldown));
    }

    #[test]
    fn test_profit_weighted_policy_never_overrides_without_expected_profit() {
        let policy = ProfitWeightedExecutionPolicy {
            enabled: true,
            roi_multiple: 1,
            risk_budget_wei: U256::from(1u64),
        };
        assert!(!policy.should_override_fail_closed(None, UncertaintyClass::RpcCooldown));
    }

    #[test]
    fn test_high_capital_override_requires_threshold_and_capital() {
        assert!(!should_override_rpc_cooldown_for_high_capital(
            true,
            None,
            U256::from(1u64)
        ));
        assert!(!should_override_rpc_cooldown_for_high_capital(
            true,
            Some(U256::from(10u64)),
            U256::ZERO
        ));
        assert!(should_override_rpc_cooldown_for_high_capital(
            true,
            Some(U256::from(10u64)),
            U256::from(10u64)
        ));
        assert!(!should_override_rpc_cooldown_for_high_capital(
            false,
            Some(U256::from(10u64)),
            U256::from(1u64)
        ));
    }
}
