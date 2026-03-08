pub fn env_first_nonempty(keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| std::env::var(key).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

pub fn parse_bool_flag(raw: &str, name: &str) -> anyhow::Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow::anyhow!("invalid {name} '{raw}': expected on/off")),
    }
}

pub fn parse_u64_flag(raw: &str, name: &str) -> anyhow::Result<u64> {
    raw.trim()
        .parse::<u64>()
        .map_err(|e| anyhow::anyhow!("invalid {name} '{raw}': {e}"))
}

pub fn parse_usize_flag(raw: &str, name: &str) -> anyhow::Result<usize> {
    raw.trim()
        .parse::<usize>()
        .map_err(|e| anyhow::anyhow!("invalid {name} '{raw}': {e}"))
}

pub fn extend_csv_strings(into: &mut Vec<String>, raw: &str) {
    into.extend(
        raw.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned),
    );
}

pub fn normalize_string_list(values: &mut Vec<String>) {
    values.retain(|value| !value.trim().is_empty());
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::{
        env_first_nonempty, extend_csv_strings, normalize_string_list, parse_bool_flag,
        parse_u64_flag, parse_usize_flag,
    };
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn env_first_nonempty_returns_first_populated_value() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::remove_var("CLI_TEST_A");
        std::env::remove_var("CLI_TEST_B");
        std::env::set_var("CLI_TEST_B", " https://rpc.example ");

        assert_eq!(
            env_first_nonempty(&["CLI_TEST_A", "CLI_TEST_B"]).as_deref(),
            Some("https://rpc.example")
        );

        std::env::remove_var("CLI_TEST_B");
    }

    #[test]
    fn parse_helpers_validate_expected_types() {
        assert!(parse_bool_flag("on", "flag").expect("bool"));
        assert_eq!(parse_u64_flag("42", "count").expect("u64"), 42);
        assert_eq!(parse_usize_flag("7", "cap").expect("usize"), 7);
    }

    #[test]
    fn csv_helpers_split_and_dedupe_entries() {
        let mut values = vec!["https://b.example".to_string()];
        extend_csv_strings(&mut values, "https://a.example, https://b.example");
        normalize_string_list(&mut values);
        assert_eq!(
            values,
            vec![
                "https://a.example".to_string(),
                "https://b.example".to_string()
            ]
        );
    }
}
