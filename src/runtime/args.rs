use alloy::primitives::Address;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorProfile {
    Auto,
    Fast,
    Balanced,
    Deep,
    Live,
}

impl OperatorProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Deep => "deep",
            Self::Live => "live",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "fast" => Some(Self::Fast),
            "balanced" => Some(Self::Balanced),
            "deep" => Some(Self::Deep),
            "live" => Some(Self::Live),
            _ => None,
        }
    }
}

fn profile_default_from_env() -> OperatorProfile {
    std::env::var("DARK_OPERATOR_PROFILE")
        .ok()
        .and_then(|raw| OperatorProfile::parse(&raw))
        .unwrap_or(OperatorProfile::Auto)
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeArgs {
    pub manual_target: Option<Address>,
    pub profile: OperatorProfile,
    pub explain_config: bool,
}

fn parse_bool_flag(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_manual_target_from_env() -> anyhow::Result<Option<Address>> {
    let raw = std::env::var("TARGET_ADDRESS").ok();
    match raw {
        Some(value) if !value.trim().is_empty() => {
            let trimmed = value.trim();
            let parsed = Address::from_str(trimmed).map_err(|err| {
                anyhow::anyhow!(
                    "invalid TARGET_ADDRESS '{}': {} (set a valid 0x-prefixed address or leave empty)",
                    trimmed,
                    err
                )
            })?;
            Ok(Some(parsed))
        }
        _ => Ok(None),
    }
}

fn parse_runtime_args_from_iter<I, S>(args: I) -> anyhow::Result<RuntimeArgs>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let supplied_args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect::<Vec<_>>();
    if !supplied_args.is_empty() {
        let joined = supplied_args.join(" ");
        return Err(anyhow::anyhow!(
            "CLI arguments are disabled in this build. Configure .env keys instead (DARK_OPERATOR_PROFILE, DARK_DISCOVERY_MODE, TARGET_ADDRESS, DASHBOARD_EXPLAIN_CONFIG). Received args: {}",
            joined
        ));
    }

    let manual_target = parse_manual_target_from_env()?;
    let profile = profile_default_from_env();
    let explain_config = std::env::var("DASHBOARD_EXPLAIN_CONFIG")
        .ok()
        .and_then(|raw| parse_bool_flag(&raw))
        .unwrap_or(false);

    Ok(RuntimeArgs {
        manual_target,
        profile,
        explain_config,
    })
}

pub fn parse_runtime_args() -> anyhow::Result<RuntimeArgs> {
    parse_runtime_args_from_iter(std::env::args().skip(1))
}

#[cfg(test)]
mod tests {
    use super::{parse_runtime_args_from_iter, profile_default_from_env, OperatorProfile};
    use alloy::primitives::Address;
    use std::str::FromStr;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_dashboard_env() {
        for key in [
            "DARK_OPERATOR_PROFILE",
            "TARGET_ADDRESS",
            "DASHBOARD_EXPLAIN_CONFIG",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn runtime_args_default_to_auto_profile() {
        let _guard = env_lock().lock().expect("env lock");
        clear_dashboard_env();
        let parsed =
            parse_runtime_args_from_iter(Vec::<&str>::new()).expect("parse should succeed");
        assert_eq!(parsed.profile, OperatorProfile::Auto);
        assert!(parsed.manual_target.is_none());
        assert!(!parsed.explain_config);
        clear_dashboard_env();
    }

    #[test]
    fn runtime_args_parse_target_and_explain_from_env() {
        let _guard = env_lock().lock().expect("env lock");
        clear_dashboard_env();
        std::env::set_var("DARK_OPERATOR_PROFILE", "deep");
        std::env::set_var(
            "TARGET_ADDRESS",
            "0x000000000000000000000000000000000000dEaD",
        );
        std::env::set_var("DASHBOARD_EXPLAIN_CONFIG", "true");

        let parsed =
            parse_runtime_args_from_iter(Vec::<&str>::new()).expect("parse should succeed");
        assert_eq!(parsed.profile, OperatorProfile::Deep);
        assert_eq!(
            parsed.manual_target,
            Some(
                Address::from_str("0x000000000000000000000000000000000000dEaD")
                    .expect("valid address"),
            )
        );
        assert!(parsed.explain_config);

        clear_dashboard_env();
    }

    #[test]
    fn runtime_args_reject_invalid_target_address() {
        let _guard = env_lock().lock().expect("env lock");
        clear_dashboard_env();
        std::env::set_var("TARGET_ADDRESS", "not-an-address");

        let err = parse_runtime_args_from_iter(Vec::<&str>::new()).expect_err("parse should fail");
        let message = err.to_string();
        assert!(
            message.contains("invalid TARGET_ADDRESS"),
            "unexpected error message: {message}"
        );

        clear_dashboard_env();
    }

    #[test]
    fn runtime_args_reject_cli_flags() {
        let _guard = env_lock().lock().expect("env lock");
        clear_dashboard_env();
        let err =
            parse_runtime_args_from_iter(vec!["--profile", "deep"]).expect_err("parse should fail");
        assert!(
            err.to_string().contains("CLI arguments are disabled"),
            "unexpected error message: {}",
            err
        );
        clear_dashboard_env();
    }

    #[test]
    fn env_profile_default_is_used_when_valid() {
        let _guard = env_lock().lock().expect("env lock");
        clear_dashboard_env();
        std::env::set_var("DARK_OPERATOR_PROFILE", "deep");

        let profile = profile_default_from_env();
        assert_eq!(profile, OperatorProfile::Deep);

        clear_dashboard_env();
    }

    #[test]
    fn invalid_env_profile_falls_back_to_auto() {
        let _guard = env_lock().lock().expect("env lock");
        clear_dashboard_env();
        std::env::set_var("DARK_OPERATOR_PROFILE", "warp");

        let profile = profile_default_from_env();
        assert_eq!(profile, OperatorProfile::Auto);

        clear_dashboard_env();
    }
}
