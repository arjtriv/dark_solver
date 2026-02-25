use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    Auto,
    Scanner,
    Defillama,
    Basescan,
    Hybrid,
}

impl DiscoveryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Scanner => "scanner",
            Self::Defillama => "defillama",
            Self::Basescan => "basescan",
            Self::Hybrid => "hybrid",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "scanner" | "scanner-only" | "scan" => Some(Self::Scanner),
            "defillama" | "defillama-only" | "llama" => Some(Self::Defillama),
            "basescan" | "basescan-only" => Some(Self::Basescan),
            "hybrid" | "all" => Some(Self::Hybrid),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryModeReport {
    pub requested: DiscoveryMode,
    pub effective: DiscoveryMode,
    pub injected_defaults: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
struct DiscoveryTuning {
    defillama_enabled: bool,
    basescan_enabled: bool,
    scanner_only: bool,
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

fn set_env_if_missing(key: &str, value: String, injected: &mut Vec<(String, String)>) {
    if env::var_os(key).is_none() {
        env::set_var(key, &value);
        injected.push((key.to_string(), value));
    }
}

fn infer_mode_from_existing_env() -> Option<DiscoveryMode> {
    let defillama_enabled = parse_bool_env("DEFILLAMA_ENABLED")?;
    let basescan_enabled = parse_bool_env("BASESCAN_ENABLED")?;
    let scanner_only = parse_bool_env("DEFILLAMA_SCANNER_ONLY")?;
    match (defillama_enabled, basescan_enabled, scanner_only) {
        (false, false, false) => Some(DiscoveryMode::Scanner),
        (true, false, true) => Some(DiscoveryMode::Defillama),
        (false, true, true) => Some(DiscoveryMode::Basescan),
        (true, true, false) => Some(DiscoveryMode::Hybrid),
        _ => None,
    }
}

fn resolve_requested_mode() -> DiscoveryMode {
    env::var("DARK_DISCOVERY_MODE")
        .ok()
        .and_then(|raw| DiscoveryMode::parse(&raw))
        .unwrap_or(DiscoveryMode::Auto)
}

fn resolve_effective_mode(requested: DiscoveryMode) -> DiscoveryMode {
    match requested {
        DiscoveryMode::Auto => infer_mode_from_existing_env().unwrap_or(DiscoveryMode::Hybrid),
        explicit => explicit,
    }
}

fn tuning_for_mode(mode: DiscoveryMode) -> DiscoveryTuning {
    match mode {
        DiscoveryMode::Auto => DiscoveryTuning {
            defillama_enabled: true,
            basescan_enabled: true,
            scanner_only: false,
        },
        DiscoveryMode::Scanner => DiscoveryTuning {
            defillama_enabled: false,
            basescan_enabled: false,
            scanner_only: false,
        },
        DiscoveryMode::Defillama => DiscoveryTuning {
            defillama_enabled: true,
            basescan_enabled: false,
            scanner_only: true,
        },
        DiscoveryMode::Basescan => DiscoveryTuning {
            defillama_enabled: false,
            basescan_enabled: true,
            scanner_only: true,
        },
        DiscoveryMode::Hybrid => DiscoveryTuning {
            defillama_enabled: true,
            basescan_enabled: true,
            scanner_only: false,
        },
    }
}

pub fn apply_discovery_mode_defaults() -> DiscoveryModeReport {
    let requested = resolve_requested_mode();
    let effective = resolve_effective_mode(requested);
    let tuning = tuning_for_mode(effective);
    let mut injected_defaults = Vec::new();

    set_env_if_missing(
        "DARK_DISCOVERY_MODE_EFFECTIVE",
        effective.as_str().to_string(),
        &mut injected_defaults,
    );
    set_env_if_missing(
        "DEFILLAMA_ENABLED",
        if tuning.defillama_enabled {
            "true".to_string()
        } else {
            "false".to_string()
        },
        &mut injected_defaults,
    );
    set_env_if_missing(
        "BASESCAN_ENABLED",
        if tuning.basescan_enabled {
            "true".to_string()
        } else {
            "false".to_string()
        },
        &mut injected_defaults,
    );
    set_env_if_missing(
        "DEFILLAMA_SCANNER_ONLY",
        if tuning.scanner_only {
            "true".to_string()
        } else {
            "false".to_string()
        },
        &mut injected_defaults,
    );

    DiscoveryModeReport {
        requested,
        effective,
        injected_defaults,
    }
}

#[cfg(test)]
mod tests {
    use super::apply_discovery_mode_defaults;
    use super::DiscoveryMode;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_keys() {
        for key in [
            "DARK_DISCOVERY_MODE",
            "DARK_DISCOVERY_MODE_EFFECTIVE",
            "DEFILLAMA_ENABLED",
            "BASESCAN_ENABLED",
            "DEFILLAMA_SCANNER_ONLY",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn discovery_mode_defaults_to_hybrid_when_unset() {
        let _guard = env_lock().lock().expect("env lock");
        clear_keys();

        let report = apply_discovery_mode_defaults();
        assert_eq!(report.requested, DiscoveryMode::Auto);
        assert_eq!(report.effective, DiscoveryMode::Hybrid);
        assert_eq!(
            std::env::var("DEFILLAMA_ENABLED").ok().as_deref(),
            Some("true")
        );
        assert_eq!(
            std::env::var("BASESCAN_ENABLED").ok().as_deref(),
            Some("true")
        );
        assert_eq!(
            std::env::var("DEFILLAMA_SCANNER_ONLY").ok().as_deref(),
            Some("false")
        );

        clear_keys();
    }

    #[test]
    fn discovery_mode_applies_explicit_scanner_choice() {
        let _guard = env_lock().lock().expect("env lock");
        clear_keys();
        std::env::set_var("DARK_DISCOVERY_MODE", "scanner");

        let report = apply_discovery_mode_defaults();
        assert_eq!(report.effective, DiscoveryMode::Scanner);
        assert_eq!(
            std::env::var("DEFILLAMA_ENABLED").ok().as_deref(),
            Some("false")
        );
        assert_eq!(
            std::env::var("BASESCAN_ENABLED").ok().as_deref(),
            Some("false")
        );
        assert_eq!(
            std::env::var("DEFILLAMA_SCANNER_ONLY").ok().as_deref(),
            Some("false")
        );

        clear_keys();
    }

    #[test]
    fn discovery_mode_does_not_override_explicit_module_flags() {
        let _guard = env_lock().lock().expect("env lock");
        clear_keys();
        std::env::set_var("DARK_DISCOVERY_MODE", "defillama");
        std::env::set_var("BASESCAN_ENABLED", "true");

        let report = apply_discovery_mode_defaults();
        assert_eq!(report.effective, DiscoveryMode::Defillama);
        assert_eq!(
            std::env::var("BASESCAN_ENABLED").ok().as_deref(),
            Some("true")
        );
        assert!(
            !report
                .injected_defaults
                .iter()
                .any(|(key, _)| key == "BASESCAN_ENABLED"),
            "explicit module flags must not be overwritten"
        );

        clear_keys();
    }
}
