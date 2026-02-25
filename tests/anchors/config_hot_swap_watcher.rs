use std::fs;

#[test]
fn test_dashboard_env_is_single_config_surface() {
    let config_source = fs::read_to_string("src/utils/config.rs")
        .expect("src/utils/config.rs must be readable for dashboard config audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for dashboard runtime audit");

    assert!(
        config_source.contains("pub struct StrategyParams")
            && config_source.contains("MIN_EXPECTED_PROFIT_WEI")
            && !config_source.contains("load_strategy_params_from_toml")
            && !config_source.contains("strategy_config_path"),
        "config layer must read strategy knobs from environment only (no secondary config files)"
    );
    assert!(
        !main_source.contains("STRATEGY_HOT_SWAP_ENABLED")
            && !main_source.contains("STRATEGY_HOT_SWAP_POLL_MS")
            && !main_source.contains("Strategy hot-swap reloaded"),
        "main runtime must not poll config.toml; dashboard config is env-only"
    );
}
