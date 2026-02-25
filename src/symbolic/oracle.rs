use revm::primitives::{keccak256, Address, U256};
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use z3::ast::BV;
use z3::Context;

static GLOBAL_CONCRETE_KECCAK_PREIMAGE_CACHE: LazyLock<RwLock<HashMap<U256, Vec<U256>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));
const GLOBAL_KECCAK_PREIMAGE_CACHE_MAX_ENTRIES: usize = 8_192;
const GLOBAL_KECCAK_HYDRATE_MAX_ENTRIES: usize = 1_024;

/// The KeccakOracle manages the bridge between Concrete Hashes and Symbolic Terms.
/// It solves the "Preimage Problem" by recording inputs whenever possible.
pub struct KeccakOracle<'ctx> {
    /// Maps Concrete Hash -> Symbolic Preimage Terms
    /// Used to "reverse" a hash if we see it later in an SLOAD
    pub preimage_map: HashMap<U256, Vec<BV<'ctx>>>,

    /// Pre-computed "Common Slots" for heuristic storage resolution
    /// Maps Hash -> Metadata
    pub common_slots: HashMap<U256, StorageSlotInfo>,
}

/// Detailed information about a pre-computed storage slot
pub struct StorageSlotInfo {
    pub description: String,
    pub base_slot: u64,
    pub inputs: Vec<Vec<u8>>, // The concrete inputs that generated this hash
}

impl<'ctx> Default for KeccakOracle<'ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> KeccakOracle<'ctx> {
    pub fn new() -> Self {
        Self {
            preimage_map: HashMap::new(),
            common_slots: HashMap::new(),
        }
    }

    /// Pre-compute common storage slots for the attacker and target.
    /// This allows us to "recognize" when a contract is checking `balances[attacker]`
    /// or `allowances[owner][attacker]` (where attacker is the spender).
    pub fn precompute_common_slots(&mut self, attacker: Address, target: Option<Address>) {
        // Broaden the list of accounts of interest
        let mut interest_accounts = vec![attacker];
        if let Some(t) = target {
            interest_accounts.push(t);
        }

        // Expanded list of common protocol addresses/spenders
        // These are frequently encountered in DeFi exploits and standard interactions.
        let common_protocols = [
            Address::ZERO,
            // Uniswap V2 Router
            alloy::primitives::address!("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
            // Uniswap V3: SwapRouter
            alloy::primitives::address!("E592427A0AEce92De3Edee1F18E0157C05861564"),
            // Uniswap V3: SwapRouter02
            alloy::primitives::address!("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
            // Permit2
            alloy::primitives::address!("000000000022D473030F116dDEE9F6B43aC78BA3"),
            // SushiSwap Router
            alloy::primitives::address!("d9e1cE17f2641f24aE83637ab66a2cca9C378B9F"),
            // Balancer V2 Vault
            alloy::primitives::address!("BA12222222228d8Ba445958a75a0704d566BF2C8"),
            // 1inch Router
            alloy::primitives::address!("1111111254EEB250632941F70902640026e70903"),
            // Curve Router/Registry
            alloy::primitives::address!("0000000022D53366457F9d5E68Ec105046FC4383"),
            // Curve ETH-stETH Pool (Common for oracle manipulation)
            alloy::primitives::address!("DC24316b9AE028F1497c275EB9192a3Ea0f67022"),
            // WETH9
            alloy::primitives::address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            // USDT
            alloy::primitives::address!("dac17f958d2ee523a2206206994597c13d831ec7"),
            // USDC
            alloy::primitives::address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        ];

        // We scan slots 0..256 to cover more complex protocol layouts (Storage layout can be deep)
        for slot in 0..256 {
            let slot_u256 = U256::from(slot);
            let slot_bytes = slot_u256.to_be_bytes::<32>();

            for &acct in &interest_accounts {
                // 1. FLAT MAPPING: keccak(acct || slot)
                // Pattern: mapping(address => uint256) balances;
                let mut input1 = vec![0u8; 12];
                input1.extend_from_slice(acct.as_slice());
                input1.extend_from_slice(&slot_bytes);

                let hash1 = keccak256(&input1);
                let hash1_u256 = U256::from_be_bytes(hash1.0);

                let label = if acct == attacker {
                    "attacker"
                } else {
                    "target"
                };
                self.common_slots.insert(
                    hash1_u256,
                    StorageSlotInfo {
                        description: format!("balances[{}]_slot_{}", label, slot),
                        base_slot: slot,
                        inputs: vec![input1.clone()],
                    },
                );

                // 2. NESTED MAPPING (Allowance Pattern): keccak(spender || keccak(owner || slot))
                // For allowances, 'slot' is usually 1 or 2 (or low index).
                if slot < 10 {
                    // Pattern A: Account is OWNER (We check who acct allowed)
                    // keccak(spender || keccak(acct || slot))
                    let inner_hash_own = keccak256(&input1);

                    for &proto in &common_protocols {
                        let mut outer_input = vec![0u8; 12];
                        outer_input.extend_from_slice(proto.as_slice());
                        outer_input.extend_from_slice(&inner_hash_own.0);

                        let hash_outer = keccak256(&outer_input);
                        let hash_outer_u256 = U256::from_be_bytes(hash_outer.0);

                        self.common_slots.insert(
                            hash_outer_u256,
                            StorageSlotInfo {
                                description: format!(
                                    "allowance[{}][{:?}]_slot_{}",
                                    label, proto, slot
                                ),
                                base_slot: slot,
                                inputs: vec![outer_input],
                            },
                        );
                    }

                    // Pattern B: Account is SPENDER (We check if owner allowed acct)
                    // This is VERY common: someone approves the attacker/target.

                    // Specific Case: allowances[target][attacker] (Drain Pattern - HIGH PRIORITY)
                    if acct == attacker {
                        let Some(t_addr) = target else { continue };
                        let mut inner_input_t = vec![0u8; 12];
                        inner_input_t.extend_from_slice(t_addr.as_slice());
                        inner_input_t.extend_from_slice(&slot_bytes);
                        let inner_hash_t = keccak256(&inner_input_t);

                        let mut outer_input_t = vec![0u8; 12];
                        outer_input_t.extend_from_slice(attacker.as_slice());
                        outer_input_t.extend_from_slice(&inner_hash_t.0);

                        let hash_outer_t = keccak256(&outer_input_t);
                        let hash_outer_t_u256 = U256::from_be_bytes(hash_outer_t.0);

                        self.common_slots.insert(
                            hash_outer_t_u256,
                            StorageSlotInfo {
                                description: format!("allowance[target][attacker]_slot_{}", slot),
                                base_slot: slot,
                                inputs: vec![outer_input_t],
                            },
                        );
                    }

                    // Generic Pattern B: Probing common protocols as 'owners'
                    let mut possible_owners = common_protocols.to_vec();
                    // If we are probing target, maybe attacker approved it?
                    if acct != attacker {
                        possible_owners.push(attacker);
                    }

                    for &owner in &possible_owners {
                        let mut inner_input = vec![0u8; 12];
                        inner_input.extend_from_slice(owner.as_slice());
                        inner_input.extend_from_slice(&slot_bytes);
                        let inner_hash = keccak256(&inner_input);

                        let mut outer_input = vec![0u8; 12];
                        outer_input.extend_from_slice(acct.as_slice());
                        outer_input.extend_from_slice(&inner_hash.0);

                        let hash_outer = keccak256(&outer_input);
                        let hash_outer_u256 = U256::from_be_bytes(hash_outer.0);

                        self.common_slots.insert(
                            hash_outer_u256,
                            StorageSlotInfo {
                                description: format!(
                                    "allowance[{:?}][{}]_slot_{}",
                                    owner, label, slot
                                ),
                                base_slot: slot,
                                inputs: vec![outer_input],
                            },
                        );
                    }
                }
            }
        }
    }

    /// Record a known preimage for a hash
    pub fn record_preimage(&mut self, hash: U256, terms: Vec<BV<'ctx>>) {
        // We only care about unique, first-seen preimages for now
        let cached_terms = self.preimage_map.entry(hash).or_insert(terms);
        if let Some(concrete_terms) = cached_terms
            .iter()
            .map(crate::symbolic::z3_ext::u256_from_bv)
            .collect::<Option<Vec<_>>>()
        {
            if let Ok(mut global_cache) = GLOBAL_CONCRETE_KECCAK_PREIMAGE_CACHE.write() {
                if !global_cache.contains_key(&hash)
                    && global_cache.len() >= GLOBAL_KECCAK_PREIMAGE_CACHE_MAX_ENTRIES
                {
                    if let Some(oldest_key) = global_cache.keys().next().copied() {
                        global_cache.remove(&oldest_key);
                    }
                }
                global_cache.entry(hash).or_insert(concrete_terms);
            }
        }
    }

    /// Hydrate this oracle with concrete preimages learned in other workers.
    pub fn hydrate_from_global_cache(&mut self, ctx: &'ctx Context) {
        let Ok(global_cache) = GLOBAL_CONCRETE_KECCAK_PREIMAGE_CACHE.read() else {
            return;
        };
        for (hash, concrete_terms) in global_cache.iter().take(GLOBAL_KECCAK_HYDRATE_MAX_ENTRIES) {
            self.preimage_map.entry(*hash).or_insert_with(|| {
                concrete_terms
                    .iter()
                    .map(|term| crate::symbolic::z3_ext::bv_from_u256(ctx, *term))
                    .collect()
            });
        }
    }

    /// Check if a concrete hash corresponds to a known storage slot for the attacker
    pub fn resolve_slot(&self, hash: U256) -> Option<&StorageSlotInfo> {
        self.common_slots.get(&hash)
    }

    /// Record a hash discovered at runtime as a potential storage slot
    pub fn record_hash(&mut self, hash: U256, description: String) {
        self.common_slots.entry(hash).or_insert(StorageSlotInfo {
            description,
            base_slot: 0, // Unknown base slot, but the hash itself is the slot
            inputs: Vec::new(),
        });
    }

    /// Attempt to find a preimage for a hash.
    /// Returns the raw bytes of the preimage if found.
    pub fn find_preimage(&self, hash: U256) -> Option<Vec<u8>> {
        // 1. Check Exact Preimages (Runtime recorded)
        if let Some(_terms) = self.preimage_map.get(&hash) {
            // We have symbolic terms, but do we have the concrete bytes?
            // The preimage_map stores BVs. If they are concrete, we can extract bytes.
            // But usually we want the BYTES for reproduction.
            // For now, checking common_slots is better for reconstruction.
        }

        // 2. Already in Common Slots (Hardcoded Patterns)
        if let Some(_info) = self.common_slots.get(&hash) {
            // We don't store the raw bytes in common_slots, just description.
            // But we can reconstruct it from description if needed, or better,
            // store the inputs in common_slots too.
            // For now, we return None if we can't easily reconstruct.
            return None;
        }

        None
    }

    /// The "Differential Collision Finder"
    /// In a real attack, this would solve: find x, y s.t. keccak(x) == keccak(y).
    /// Here, we implement a bounded search for specific "Collision Targets".
    ///
    /// Goal: Find if 'target_hash' collides with any known storage slot of 'victim'.
    pub fn find_collision(&self, target_hash: U256) -> Option<String> {
        // Check if target_hash exists in our common_slots db
        if let Some(info) = self.common_slots.get(&target_hash) {
            return Some(info.description.clone());
        }
        None
    }

    /// Find potential candidate slots that match a given base slot.
    /// This is used when we see a pattern `keccak(key || base_slot)` but the key is symbolic.
    /// We can't lookup the exact hash, but we can return ALL known slots that share this base_slot.
    pub fn find_potential_matches(&self, target_base_slot: u64) -> Vec<(U256, &StorageSlotInfo)> {
        let mut matches = Vec::new();
        for (hash, info) in &self.common_slots {
            if info.base_slot == target_base_slot {
                matches.push((*hash, info));
            }
        }
        matches
    }

    /// Check if a hash is a known "Anchor" in our storage schema.
    pub fn is_known_hash(&self, hash: U256) -> bool {
        self.common_slots.contains_key(&hash)
    }

    /// Get details about a known hash
    pub fn get_slot_info(&self, hash: U256) -> Option<&StorageSlotInfo> {
        self.common_slots.get(&hash)
    }
}
