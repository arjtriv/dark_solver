//! Anchor Test: Batch Capital Profiler token selection + WETH parity TVL proxy.

use alloy::primitives::{Address, U256};

#[test]
fn test_capital_profiler_tokens_mainnet_prefers_weth_usdc_and_an_extra_stable() {
    let cfg = dark_solver::config::chains::ChainConfig::get(1);
    let tokens = dark_solver::scanner::capital_profiler_tokens(1);

    assert!(tokens.contains(&cfg.weth));
    assert!(tokens.contains(&cfg.usdc));

    // Mainnet config includes additional stablecoins (USDT/DAI); we should pick at least one.
    let has_extra_stable = cfg
        .stablecoins
        .iter()
        .any(|stable| *stable != cfg.usdc && tokens.contains(stable));
    assert!(has_extra_stable);
    assert!(tokens.len() <= 3);
}

#[test]
fn test_capital_profiler_tokens_base_is_bounded_and_includes_weth_usdc() {
    let cfg = dark_solver::config::chains::ChainConfig::get(8453);
    let tokens = dark_solver::scanner::capital_profiler_tokens(8453);

    assert!(tokens.contains(&cfg.weth));
    assert!(tokens.contains(&cfg.usdc));
    assert!(tokens.len() <= 3);
}

#[test]
fn test_estimate_contract_tvl_eth_wei_counts_weth_at_parity() {
    let cfg = dark_solver::config::chains::ChainConfig::get(1);
    let one_eth = U256::from(1_000_000_000_000_000_000u128);
    let tvl = dark_solver::scanner::estimate_contract_tvl_eth_wei(1, &[(cfg.weth, one_eth)]);
    assert_eq!(tvl, one_eth);
}

#[test]
fn test_estimate_contract_tvl_eth_wei_ignores_unknown_tokens() {
    let unknown = Address::new([0x42; 20]);
    let tvl =
        dark_solver::scanner::estimate_contract_tvl_eth_wei(1, &[(unknown, U256::from(1u64))]);
    assert_eq!(tvl, U256::ZERO);
}
