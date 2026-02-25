use crate::storage::contracts_db::ContractsDb;
use dashmap::DashMap;
use revm::primitives::{Address, Bytes};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasGriefClass {
    OutOfGas,
    HighRevertGas,
}

impl GasGriefClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            GasGriefClass::OutOfGas => "out_of_gas",
            GasGriefClass::HighRevertGas => "high_revert_gas",
        }
    }

    pub(crate) fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "out_of_gas" => Some(Self::OutOfGas),
            "high_revert_gas" => Some(Self::HighRevertGas),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GasGriefEntry {
    pub contract: Address,
    pub selector: [u8; 4],
    pub class: GasGriefClass,
    pub reason: String,
    pub gas_used: u64,
    pub gas_limit: u64,
}

static GAS_GRIEF_BLOCKLIST: LazyLock<DashMap<(Address, [u8; 4]), GasGriefEntry>> =
    LazyLock::new(|| DashMap::with_capacity(2048));

static GAS_GRIEF_DB: LazyLock<Option<ContractsDb>> =
    LazyLock::new(|| ContractsDb::open_default().ok());

pub fn selector_from_call_data(call_data: &Bytes) -> Option<[u8; 4]> {
    crate::solver::honeypot::selector_from_call_data(call_data)
}

#[derive(Debug, Clone)]
pub struct ShadowFailureReport {
    pub success: bool,
    pub failure_gas_used: Option<u64>,
    pub failure_gas_limit: Option<u64>,
    pub halt_reason: Option<String>,
}

fn load_gas_grief_revert_gas_used_bps() -> u64 {
    std::env::var("GAS_GRIEF_REVERT_GAS_USED_BPS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 10_000)
        .unwrap_or(9_500)
}

fn is_out_of_gas_halt_reason(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    r.contains("outofgas") || r.contains("out_of_gas") || r.contains("out of gas")
}

pub fn classify_shadow_failure(
    report: &ShadowFailureReport,
) -> Option<(GasGriefClass, String, u64, u64)> {
    if report.success {
        return None;
    }
    let gas_used = report.failure_gas_used.unwrap_or(0);
    let gas_limit = report.failure_gas_limit.unwrap_or(0);
    if let Some(reason) = report.halt_reason.as_deref() {
        if is_out_of_gas_halt_reason(reason) {
            return Some((
                GasGriefClass::OutOfGas,
                format!("halt={reason}"),
                gas_used,
                gas_limit,
            ));
        }
    }
    if gas_limit > 0 {
        let bps = load_gas_grief_revert_gas_used_bps();
        let threshold = gas_limit.saturating_mul(bps) / 10_000;
        if gas_used >= threshold {
            return Some((
                GasGriefClass::HighRevertGas,
                format!("gas_used={gas_used} >= {bps}bps of gas_limit={gas_limit}"),
                gas_used,
                gas_limit,
            ));
        }
    }
    None
}

pub fn is_gas_grief_selector(contract: Address, call_data: &Bytes) -> bool {
    let Some(selector) = selector_from_call_data(call_data) else {
        return false;
    };
    if GAS_GRIEF_BLOCKLIST.contains_key(&(contract, selector)) {
        return true;
    }
    let Some(db) = GAS_GRIEF_DB.as_ref() else {
        return false;
    };
    match db.lookup_gas_grief_sieve(contract, selector) {
        Ok(Some(entry)) => {
            GAS_GRIEF_BLOCKLIST.insert((contract, selector), entry);
            true
        }
        _ => false,
    }
}

pub fn record_gas_grief(
    contract: Address,
    call_data: &Bytes,
    class: GasGriefClass,
    reason: impl Into<String>,
    gas_used: u64,
    gas_limit: u64,
) {
    let Some(selector) = selector_from_call_data(call_data) else {
        return;
    };
    let entry = GasGriefEntry {
        contract,
        selector,
        class,
        reason: reason.into(),
        gas_used,
        gas_limit,
    };
    GAS_GRIEF_BLOCKLIST.insert((contract, selector), entry.clone());
    if let Some(db) = GAS_GRIEF_DB.as_ref() {
        let _ = db.upsert_gas_grief_sieve(&entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_grief_class_roundtrip() {
        assert_eq!(
            GasGriefClass::from_str(GasGriefClass::OutOfGas.as_str()),
            Some(GasGriefClass::OutOfGas)
        );
        assert_eq!(
            GasGriefClass::from_str(GasGriefClass::HighRevertGas.as_str()),
            Some(GasGriefClass::HighRevertGas)
        );
        assert!(GasGriefClass::from_str("nope").is_none());
    }

    #[test]
    fn test_classify_shadow_failure_out_of_gas() {
        let report = ShadowFailureReport {
            success: false,
            failure_gas_used: Some(2_000_000),
            failure_gas_limit: Some(2_000_000),
            halt_reason: Some("OutOfGas".to_string()),
        };
        let (class, _reason, gas_used, gas_limit) =
            classify_shadow_failure(&report).expect("must classify");
        assert_eq!(class, GasGriefClass::OutOfGas);
        assert_eq!(gas_used, 2_000_000);
        assert_eq!(gas_limit, 2_000_000);
    }

    #[test]
    fn test_classify_shadow_failure_high_revert_gas() {
        std::env::set_var("GAS_GRIEF_REVERT_GAS_USED_BPS", "9500");
        let report = ShadowFailureReport {
            success: false,
            failure_gas_used: Some(1_950_000),
            failure_gas_limit: Some(2_000_000),
            halt_reason: None,
        };
        let (class, _reason, _gas_used, _gas_limit) =
            classify_shadow_failure(&report).expect("must classify");
        assert_eq!(class, GasGriefClass::HighRevertGas);
        std::env::remove_var("GAS_GRIEF_REVERT_GAS_USED_BPS");
    }
}
