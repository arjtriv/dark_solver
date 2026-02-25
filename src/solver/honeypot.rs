use crate::storage::contracts_db::ContractsDb;
use dashmap::DashMap;
use revm::primitives::{Address, Bytes};
use std::sync::{LazyLock, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotClass {
    AdminKeyRequired,
}

impl HoneypotClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            HoneypotClass::AdminKeyRequired => "admin_key_required",
        }
    }

    pub(crate) fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "admin_key_required" => Some(Self::AdminKeyRequired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HoneypotEntry {
    pub contract: Address,
    pub selector: [u8; 4],
    pub class: HoneypotClass,
    pub reason: String,
}

static HONEYPOT_BLOCKLIST: LazyLock<DashMap<(Address, [u8; 4]), HoneypotEntry>> =
    LazyLock::new(|| DashMap::with_capacity(1024));

enum HoneypotDbState {
    Ready(ContractsDb),
    Unavailable(String),
}

static HONEYPOT_DB: LazyLock<HoneypotDbState> =
    LazyLock::new(|| match ContractsDb::open_default() {
        Ok(db) => HoneypotDbState::Ready(db),
        Err(err) => HoneypotDbState::Unavailable(err.to_string()),
    });

fn honeypot_db_required() -> bool {
    std::env::var("HONEYPOT_DB_REQUIRED")
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn log_honeypot_db_unavailable_once(reason: &str) {
    static WARN_ONCE: OnceLock<()> = OnceLock::new();
    if WARN_ONCE.set(()).is_ok() {
        tracing::warn!(
            "[WARN] honeypot DB unavailable; selector sieve degraded: {}",
            reason
        );
    }
}

pub fn selector_from_call_data(call_data: &Bytes) -> Option<[u8; 4]> {
    if call_data.len() < 4 {
        return None;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&call_data[..4]);
    Some(selector)
}

pub fn is_admin_key_required_revert(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "ownable: caller is not the owner",
        "caller is not the owner",
        "only owner",
        "onlyowner",
        "not owner",
        "accesscontrol:",
        "missing role",
        "requires role",
        "unauthorized",
        "not authorized",
        "only admin",
        "onlyadmin",
        "caller is not admin",
        "not governor",
        "only governor",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

pub fn is_honeypot_selector(contract: Address, call_data: &Bytes) -> bool {
    let Some(selector) = selector_from_call_data(call_data) else {
        return false;
    };
    if HONEYPOT_BLOCKLIST.contains_key(&(contract, selector)) {
        return true;
    }
    match &*HONEYPOT_DB {
        HoneypotDbState::Ready(db) => match db.lookup_honeypot_sieve(contract, selector) {
            Ok(Some(entry)) => {
                HONEYPOT_BLOCKLIST.insert((contract, selector), entry);
                true
            }
            _ => false,
        },
        HoneypotDbState::Unavailable(reason) => {
            log_honeypot_db_unavailable_once(reason);
            honeypot_db_required()
        }
    }
}

pub fn record_admin_key_required(contract: Address, call_data: &Bytes, reason: impl Into<String>) {
    let Some(selector) = selector_from_call_data(call_data) else {
        return;
    };
    let entry = HoneypotEntry {
        contract,
        selector,
        class: HoneypotClass::AdminKeyRequired,
        reason: reason.into(),
    };
    HONEYPOT_BLOCKLIST.insert((contract, selector), entry.clone());
    if let HoneypotDbState::Ready(db) = &*HONEYPOT_DB {
        let _ = db.upsert_honeypot_sieve(&entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_key_required_revert_classifier() {
        assert!(is_admin_key_required_revert(
            "Ownable: caller is not the owner"
        ));
        assert!(is_admin_key_required_revert(
            "AccessControl: account is missing role"
        ));
        assert!(is_admin_key_required_revert("unauthorized"));
        assert!(!is_admin_key_required_revert(
            "insufficient funds for gas * price + value"
        ));
    }

    #[test]
    fn test_selector_from_call_data() {
        let call = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x01]);
        assert_eq!(
            selector_from_call_data(&call),
            Some([0xde, 0xad, 0xbe, 0xef])
        );
        let short = Bytes::from_static(&[0x01, 0x02, 0x03]);
        assert!(selector_from_call_data(&short).is_none());
    }

    #[test]
    fn test_honeypot_class_roundtrip() {
        assert_eq!(
            HoneypotClass::from_str(HoneypotClass::AdminKeyRequired.as_str()),
            Some(HoneypotClass::AdminKeyRequired)
        );
        assert!(HoneypotClass::from_str("nope").is_none());
    }
}
