use alloy::primitives::Address;
use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;

pub mod aave_v3;
pub mod balancer;
pub mod uniswap_v2;
pub mod uniswap_v3;

pub use self::aave_v3::AaveV3Provider;
pub use self::balancer::BalancerProvider;
pub use self::uniswap_v2::UniswapV2PairProvider;
pub use self::uniswap_v3::UniswapV3PoolProvider;

#[derive(Debug, Clone, Copy)]
pub enum FlashLoanProviderKind {
    AaveV3,
    BalancerVault,
    UniswapV2Pair,
    UniswapV3Pool,
}

#[derive(Debug, Clone, Copy)]
pub struct FlashLoanProviderSpec {
    pub address: Address,
    pub fee_bps: u32,
    pub kind: FlashLoanProviderKind,
    pub token0: Option<Address>,
    pub token1: Option<Address>,
}

static DEFAULT_PROVIDER_SPECS: [FlashLoanProviderSpec; 2] = [
    FlashLoanProviderSpec {
        // Base Aave V3 Pool
        address: alloy::primitives::address!("A238Dd80C259a72e81d7e4664a9801593F98d1c5"),
        fee_bps: 9,
        kind: FlashLoanProviderKind::AaveV3,
        token0: None,
        token1: None,
    },
    FlashLoanProviderSpec {
        // Base Balancer Vault
        address: alloy::primitives::address!("BA12222222228d8Ba445958a75a0704d566BF2C8"),
        fee_bps: 0,
        kind: FlashLoanProviderKind::BalancerVault,
        token0: None,
        token1: None,
    },
];

pub fn default_provider_specs() -> &'static [FlashLoanProviderSpec] {
    // Keep this centralized so solver modeling and executor wiring share the same provider set.
    &DEFAULT_PROVIDER_SPECS
}

fn default_provider_specs_for_chain(chain_id: u64) -> Vec<FlashLoanProviderSpec> {
    match chain_id {
        // Keep Base defaults explicit and deterministic.
        8453 => DEFAULT_PROVIDER_SPECS.to_vec(),
        // Other chains are env-driven by default.
        _ => Vec::new(),
    }
}

fn parse_provider_kind(raw: &str) -> Option<FlashLoanProviderKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "aave" | "aavev3" | "aave_v3" => Some(FlashLoanProviderKind::AaveV3),
        "balancer" | "balancer_vault" | "balancer-vault" => {
            Some(FlashLoanProviderKind::BalancerVault)
        }
        "uniswap_v2_pair" | "uniswap-v2-pair" | "uni_v2_pair" | "v2_pair" => {
            Some(FlashLoanProviderKind::UniswapV2Pair)
        }
        "uniswap_v3_pool" | "uniswap-v3-pool" | "uni_v3_pool" | "v3_pool" => {
            Some(FlashLoanProviderKind::UniswapV3Pool)
        }
        _ => None,
    }
}

fn parse_provider_triplet(entry: &str) -> Option<(Address, Address, Address, Option<u32>)> {
    // Format:
    // - V2: pair:token0:token1
    // - V3: pool:token0:token1[:fee_bps]
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parts = trimmed.split(':').map(|p| p.trim()).collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }
    let addr = Address::from_str(parts[0]).ok()?;
    let token0 = Address::from_str(parts[1]).ok()?;
    let token1 = Address::from_str(parts[2]).ok()?;
    let fee_bps = if parts.len() >= 4 {
        parts[3].parse::<u32>().ok()
    } else {
        None
    };
    Some((addr, token0, token1, fee_bps))
}

fn load_flash_swap_specs_from_env() -> Vec<FlashLoanProviderSpec> {
    let mut out = Vec::new();

    if let Ok(raw) = std::env::var("FLASH_SWAP_V2_PAIRS") {
        for item in raw.split(';') {
            let Some((addr, token0, token1, _fee)) = parse_provider_triplet(item) else {
                continue;
            };
            out.push(FlashLoanProviderSpec {
                address: addr,
                fee_bps: 0,
                kind: FlashLoanProviderKind::UniswapV2Pair,
                token0: Some(token0),
                token1: Some(token1),
            });
        }
    }

    if let Ok(raw) = std::env::var("FLASH_SWAP_V3_POOLS") {
        for item in raw.split(';') {
            let Some((addr, token0, token1, fee_bps)) = parse_provider_triplet(item) else {
                continue;
            };
            out.push(FlashLoanProviderSpec {
                address: addr,
                fee_bps: fee_bps.unwrap_or(0),
                kind: FlashLoanProviderKind::UniswapV3Pool,
                token0: Some(token0),
                token1: Some(token1),
            });
        }
    }

    out
}

fn parse_provider_registry_entry(entry: &str) -> Option<FlashLoanProviderSpec> {
    // Format:
    // - aave_v3:pool_address[:fee_bps]
    // - balancer_vault:vault_address[:fee_bps]
    // - uniswap_v2_pair:pair:token0:token1[:fee_bps]
    // - uniswap_v3_pool:pool:token0:token1[:fee_bps]
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parts = trimmed.split(':').map(|p| p.trim()).collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    let kind = parse_provider_kind(parts[0])?;
    let address = Address::from_str(parts[1]).ok()?;
    match kind {
        FlashLoanProviderKind::AaveV3 | FlashLoanProviderKind::BalancerVault => {
            let default_fee_bps = if matches!(kind, FlashLoanProviderKind::AaveV3) {
                9
            } else {
                0
            };
            let fee_bps = parts
                .get(2)
                .and_then(|raw| raw.parse::<u32>().ok())
                .unwrap_or(default_fee_bps);
            Some(FlashLoanProviderSpec {
                address,
                fee_bps,
                kind,
                token0: None,
                token1: None,
            })
        }
        FlashLoanProviderKind::UniswapV2Pair | FlashLoanProviderKind::UniswapV3Pool => {
            if parts.len() < 4 {
                return None;
            }
            let token0 = Address::from_str(parts[2]).ok()?;
            let token1 = Address::from_str(parts[3]).ok()?;
            let fee_bps = parts
                .get(4)
                .and_then(|raw| raw.parse::<u32>().ok())
                .unwrap_or(0);
            Some(FlashLoanProviderSpec {
                address,
                fee_bps,
                kind,
                token0: Some(token0),
                token1: Some(token1),
            })
        }
    }
}

fn load_provider_specs_from_registry_env(chain_id: u64) -> Vec<FlashLoanProviderSpec> {
    let chain_key = format!("FLASH_LOAN_PROVIDER_SPECS_{chain_id}");
    let raw = std::env::var(chain_key)
        .ok()
        .or_else(|| std::env::var("FLASH_LOAN_PROVIDER_SPECS").ok());
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(';')
        .filter_map(parse_provider_registry_entry)
        .collect()
}

pub fn provider_specs_for_chain(chain_id: u64) -> Vec<FlashLoanProviderSpec> {
    let mut out = default_provider_specs_for_chain(chain_id);
    out.extend(load_flash_swap_specs_from_env());
    out.extend(load_provider_specs_from_registry_env(chain_id));

    // De-duplicate by address with "last writer wins" semantics so env can override defaults.
    let mut seen = HashSet::new();
    let mut dedup_rev = Vec::new();
    for spec in out.into_iter().rev() {
        if seen.insert(spec.address) {
            dedup_rev.push(spec);
        }
    }
    dedup_rev.reverse();
    dedup_rev
}

pub fn provider_specs_for_modeling() -> Vec<FlashLoanProviderSpec> {
    // Backward-compatible helper for tests/anchors that do not thread chain-id.
    let fallback_chain = std::env::var("CHAIN_ID")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(8453);
    provider_specs_for_chain(fallback_chain)
}

pub trait FlashLoanProvider: Send + Sync {
    fn name(&self) -> &str;
    fn address(&self) -> Address;
    fn fee_bps(&self) -> u32;
    fn encode_loan(
        &self,
        token: Address,
        amount: alloy::primitives::U256,
        target: Address,
        calldata: alloy::primitives::Bytes,
    ) -> anyhow::Result<alloy::primitives::Bytes>;
}

pub fn get_default_providers(chain_id: u64) -> HashMap<Address, Box<dyn FlashLoanProvider>> {
    let mut providers: HashMap<Address, Box<dyn FlashLoanProvider>> = HashMap::new();

    for spec in provider_specs_for_chain(chain_id) {
        match spec.kind {
            FlashLoanProviderKind::AaveV3 => {
                providers.insert(
                    spec.address,
                    Box::new(AaveV3Provider {
                        pool_address: spec.address,
                    }),
                );
            }
            FlashLoanProviderKind::BalancerVault => {
                providers.insert(
                    spec.address,
                    Box::new(BalancerProvider {
                        vault_address: spec.address,
                    }),
                );
            }
            FlashLoanProviderKind::UniswapV2Pair => {
                let (Some(token0), Some(token1)) = (spec.token0, spec.token1) else {
                    continue;
                };
                let chain_weth = crate::config::chains::ChainConfig::get(chain_id).weth;
                providers.insert(
                    spec.address,
                    Box::new(UniswapV2PairProvider {
                        pair_address: spec.address,
                        token0,
                        token1,
                        chain_weth,
                    }),
                );
            }
            FlashLoanProviderKind::UniswapV3Pool => {
                let (Some(token0), Some(token1)) = (spec.token0, spec.token1) else {
                    continue;
                };
                let chain_weth = crate::config::chains::ChainConfig::get(chain_id).weth;
                providers.insert(
                    spec.address,
                    Box::new(UniswapV3PoolProvider {
                        pool_address: spec.address,
                        token0,
                        token1,
                        fee_bps: spec.fee_bps,
                        chain_weth,
                    }),
                );
            }
        }
    }

    providers
}

#[cfg(test)]
mod tests {
    use super::{provider_specs_for_chain, FlashLoanProviderKind};
    use alloy::primitives::Address;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_provider_specs_for_chain_keeps_base_defaults() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("FLASH_LOAN_PROVIDER_SPECS_8453");
        std::env::remove_var("FLASH_LOAN_PROVIDER_SPECS");
        std::env::remove_var("FLASH_SWAP_V2_PAIRS");
        std::env::remove_var("FLASH_SWAP_V3_POOLS");

        let specs = provider_specs_for_chain(8453);
        assert!(specs
            .iter()
            .any(|spec| matches!(spec.kind, FlashLoanProviderKind::AaveV3)));
        assert!(specs
            .iter()
            .any(|spec| matches!(spec.kind, FlashLoanProviderKind::BalancerVault)));
    }

    #[test]
    fn test_provider_specs_for_chain_accepts_registry_env_entries() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var(
            "FLASH_LOAN_PROVIDER_SPECS_8453",
            "aave_v3:0x1111111111111111111111111111111111111111:12;uniswap_v2_pair:0x2222222222222222222222222222222222222222:0x3333333333333333333333333333333333333333:0x4444444444444444444444444444444444444444:0",
        );
        let specs = provider_specs_for_chain(8453);
        std::env::remove_var("FLASH_LOAN_PROVIDER_SPECS_8453");

        let aave = Address::from([0x11; 20]);
        let pair = Address::from([0x22; 20]);
        assert!(specs.iter().any(|spec| spec.address == aave));
        assert!(specs.iter().any(|spec| spec.address == pair));
    }
}
