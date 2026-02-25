//! Anchor: TVL-weighted target acquisition must be decimals-aware (stablecoins) and
//! default to a ~$1M USD threshold expressed in ETH-wei.

use alloy::primitives::U256;
use dark_solver::config::chains::ChainConfig;

fn save_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn restore_env(key: &str, value: Option<String>) {
    match value {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

#[test]
fn tvl_usd_threshold_converts_to_eth_wei_using_profit_eth_usd() {
    let old_tvl_usd = save_env("HIGH_VALUE_TVL_USD");
    let old_tvl_wei = save_env("HIGH_VALUE_TVL_WEI");
    let old_eth_usd = save_env("PROFIT_ETH_USD");

    std::env::remove_var("HIGH_VALUE_TVL_WEI");
    std::env::set_var("HIGH_VALUE_TVL_USD", "1000000");
    std::env::set_var("PROFIT_ETH_USD", "3000");

    let threshold = dark_solver::scanner::high_value_tvl_threshold_wei();
    // stable_price_eth_wei = floor(1e18 / 3000); threshold = usd * stable_price_eth_wei
    let stable_price_eth_wei = U256::from(1_000_000_000_000_000_000u128) / U256::from(3_000u128);
    let expected = U256::from(1_000_000u128).saturating_mul(stable_price_eth_wei);
    assert_eq!(threshold, expected);

    restore_env("HIGH_VALUE_TVL_USD", old_tvl_usd);
    restore_env("HIGH_VALUE_TVL_WEI", old_tvl_wei);
    restore_env("PROFIT_ETH_USD", old_eth_usd);
}

#[test]
fn tvl_estimate_counts_usdc_with_decimals_and_stable_price_proxy() {
    let old_eth_usd = save_env("PROFIT_ETH_USD");
    let old_stable_price = save_env("PROFIT_STABLE_TOKEN_ETH_WEI");

    // Force stable proxy path.
    std::env::remove_var("PROFIT_STABLE_TOKEN_ETH_WEI");
    std::env::set_var("PROFIT_ETH_USD", "3000");

    let chain = ChainConfig::base();
    let one_million_usdc_raw = U256::from(1_000_000u128).saturating_mul(U256::from(1_000_000u128));
    let balances = vec![(chain.usdc, one_million_usdc_raw)];

    let tvl = dark_solver::scanner::estimate_contract_tvl_eth_wei(chain.chain_id, &balances);

    // 1,000,000 USD valued through stable proxy: usd * floor(1e18/eth_usd).
    let stable_price_eth_wei = U256::from(1_000_000_000_000_000_000u128) / U256::from(3_000u128);
    let expected = U256::from(1_000_000u128).saturating_mul(stable_price_eth_wei);
    assert_eq!(tvl, expected);

    restore_env("PROFIT_ETH_USD", old_eth_usd);
    restore_env("PROFIT_STABLE_TOKEN_ETH_WEI", old_stable_price);
}
