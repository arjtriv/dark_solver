use alloy::primitives::{address, Address};

const MAINNET_PRIVATE_BUILDERS: &[&str] = &[
    "https://relay.flashbots.net",
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
];

const BASE_PRIVATE_BUILDERS: &[&str] = &[
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
    "https://relay.flashbots.net",
];

const ARBITRUM_PRIVATE_BUILDERS: &[&str] = &[
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
    "https://relay.flashbots.net",
];

const BSC_PRIVATE_BUILDERS: &[&str] = &[
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
];

const POLYGON_PRIVATE_BUILDERS: &[&str] = &[
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
];

const OPTIMISM_PRIVATE_BUILDERS: &[&str] = &[
    "https://rpc.beaverbuild.org",
    "https://rpc.titanbuilder.xyz",
    "https://relay.flashbots.net",
];

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub name: String,
    pub weth: Address,
    pub usdc: Address,
    pub stablecoins: Vec<Address>,
    pub known_tokens: Vec<Address>,
    pub block_time_ms: u64,
    pub max_bundle_gas: u64,
}

impl ChainConfig {
    pub fn get(chain_id: u64) -> Self {
        match chain_id {
            1 => Self::mainnet(),
            8453 => Self::base(),
            42161 => Self::arbitrum(),
            56 => Self::bsc(),
            137 => Self::polygon(),
            10 => Self::optimism(),
            _ => Self::base(),
        }
    }

    pub fn mainnet() -> Self {
        Self {
            chain_id: 1,
            name: "Ethereum Mainnet".to_string(),
            weth: address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            usdc: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            stablecoins: vec![
                address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                address!("dAC17F958D2ee523a2206206994597C13D831ec7"),
                address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
            ],
            known_tokens: vec![
                address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
                address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            ],
            block_time_ms: 12_000,
            max_bundle_gas: 15_000_000,
        }
    }

    pub fn default_private_builder_urls(chain_id: u64) -> Vec<String> {
        let urls = match chain_id {
            1 => MAINNET_PRIVATE_BUILDERS,
            8453 => BASE_PRIVATE_BUILDERS,
            42161 => ARBITRUM_PRIVATE_BUILDERS,
            56 => BSC_PRIVATE_BUILDERS,
            137 => POLYGON_PRIVATE_BUILDERS,
            10 => OPTIMISM_PRIVATE_BUILDERS,
            _ => BASE_PRIVATE_BUILDERS,
        };
        urls.iter().map(|url| (*url).to_string()).collect()
    }

    pub fn private_builder_urls(&self) -> Vec<String> {
        Self::default_private_builder_urls(self.chain_id)
    }

    pub fn base() -> Self {
        Self {
            chain_id: 8453,
            name: "Base".to_string(),
            weth: address!("4200000000000000000000000000000000000006"),
            usdc: address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            stablecoins: vec![address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")],
            known_tokens: vec![
                address!("4200000000000000000000000000000000000006"),
                address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            ],
            block_time_ms: 2_000,
            max_bundle_gas: 20_000_000,
        }
    }

    pub fn arbitrum() -> Self {
        Self {
            chain_id: 42161,
            name: "Arbitrum One".to_string(),
            weth: address!("82aF49447D8a07e3bd95BD0d56f35241523fBab1"),
            usdc: address!("af88d065e77c8cC2239327C5EDb3A432268e5831"),
            stablecoins: vec![
                address!("af88d065e77c8cC2239327C5EDb3A432268e5831"),
                address!("Fdc06022312910345eF47F405E524F495145b2f8"),
            ],
            known_tokens: vec![
                address!("82aF49447D8a07e3bd95BD0d56f35241523fBab1"),
                address!("af88d065e77c8cC2239327C5EDb3A432268e5831"),
            ],
            block_time_ms: 250,
            max_bundle_gas: 32_000_000,
        }
    }

    pub fn bsc() -> Self {
        Self {
            chain_id: 56,
            name: "BNB Smart Chain".to_string(),
            weth: address!("bb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
            usdc: address!("8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
            stablecoins: vec![
                address!("8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
                address!("55d398326f99059fF775485246999027B3197955"),
                address!("e9e7CEA3DedcA5984780Bafc599bD69ADd087D56"),
            ],
            known_tokens: vec![address!("bb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")],
            block_time_ms: 3_000,
            max_bundle_gas: 30_000_000,
        }
    }

    pub fn polygon() -> Self {
        Self {
            chain_id: 137,
            name: "Polygon".to_string(),
            weth: address!("7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"),
            usdc: address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"),
            stablecoins: vec![
                address!("2791Bca1f2de4661ED88A30C99A7a9449Aa84174"),
                address!("c2132D05D31c914a87C6611C10748AEb04B58e8F"),
            ],
            known_tokens: vec![address!("0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270")],
            block_time_ms: 2_000,
            max_bundle_gas: 30_000_000,
        }
    }

    pub fn optimism() -> Self {
        Self {
            chain_id: 10,
            name: "Optimism".to_string(),
            weth: address!("4200000000000000000000000000000000000006"),
            usdc: address!("0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
            stablecoins: vec![address!("0b2C639c533813f4Aa9D7837CAf62653d097Ff85")],
            known_tokens: vec![address!("4200000000000000000000000000000000000006")],
            block_time_ms: 2_000,
            max_bundle_gas: 30_000_000,
        }
    }
}
