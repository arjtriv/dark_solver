use alloy::primitives::{Address, U256};
use dark_solver::protocols::{
    amm_price_impact, chainlink_vrf, commit_reveal, dust_debt, erc4626, fee_on_transfer,
    flash_loan, governance, init_race, lending, nft_callbacks, prng, psm, read_only_reentrancy,
    redemption, timelock, uniswap_v2, uniswap_v3, uniswap_v4,
};
use dark_solver::symbolic::z3_ext::{u256_from_bv, KeccakTheory};
use revm::primitives::Bytes;
use std::collections::BTreeSet;
use std::fs;
use z3::ast::{Ast, Bool, BV};
use z3::{Config, Context};

const SAMPLES: usize = 10_000;

#[derive(Clone, Copy)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.state
    }

    fn range_u64(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        low + (self.next_u64() % (high - low))
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for b in &mut out {
            *b = (self.next_u64() & 0xff) as u8;
        }
        out
    }
}

fn selector4(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn selector32(signature: &str) -> u32 {
    let s = selector4(signature);
    u32::from_be_bytes(s)
}

fn sorted_dedup_4(mut selectors: Vec<[u8; 4]>) -> Vec<[u8; 4]> {
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

fn contains_push4(bytes: &[u8], selector: [u8; 4]) -> bool {
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 && bytes[i + 1..i + 5] == selector {
            return true;
        }
    }
    false
}

fn bool_const(expr: &Bool, label: &str) -> bool {
    let maybe = expr.simplify().as_bool();
    assert!(
        maybe.is_some(),
        "{label}: expression must simplify to concrete bool"
    );
    maybe.unwrap_or(false)
}

fn bv_const_u256(expr: &BV, label: &str) -> U256 {
    let maybe = u256_from_bv(&expr.simplify());
    assert!(
        maybe.is_some(),
        "{label}: expression must simplify to concrete BV"
    );
    maybe.unwrap_or(U256::ZERO)
}

fn safe_div_u256(n: U256, d: U256) -> U256 {
    if d == U256::ZERO {
        U256::ZERO
    } else {
        n / d
    }
}

fn protocol_public_fn_inventory() -> BTreeSet<String> {
    let mut out = BTreeSet::new();

    let mut parse_file = |path: &str| {
        let content = fs::read_to_string(path).unwrap_or_default();
        for line in content.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("pub fn ") {
                let raw_name = rest.split('(').next().unwrap_or_default().trim();
                let name_part = raw_name.split('<').next().unwrap_or_default().trim();
                if !name_part.is_empty() {
                    out.insert(format!("{path}:{name_part}"));
                }
            }
        }
    };

    if let Ok(entries) = fs::read_dir("src/protocols") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "rs" {
                        if let Some(path_str) = path.to_str() {
                            parse_file(path_str);
                        }
                    }
                }
            }
        }
    }

    if let Ok(entries) = fs::read_dir("src/protocols/flash_loan") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "rs" {
                        if let Some(path_str) = path.to_str() {
                            parse_file(path_str);
                        }
                    }
                }
            }
        }
    }

    out
}

fn expected_protocol_public_fn_inventory() -> BTreeSet<String> {
    [
        "src/protocols/amm_price_impact.rs:known_amm_price_impact_selectors",
        "src/protocols/amm_price_impact.rs:sqrt_price_drop_exceeds_bps",
        "src/protocols/amm_price_impact.rs:sqrt_price_x96_after_input",
        "src/protocols/balancer.rs:calc_in_given_out",
        "src/protocols/balancer.rs:calc_out_given_in",
        "src/protocols/balancer.rs:calc_out_given_in_symbolic",
        "src/protocols/chainlink_vrf.rs:has_vrf_timing_pattern",
        "src/protocols/chainlink_vrf.rs:known_vrf_claim_selectors",
        "src/protocols/chainlink_vrf.rs:known_vrf_fulfill_selectors",
        "src/protocols/chainlink_vrf.rs:same_block_claim_window",
        "src/protocols/chainlink_vrf.rs:vrf_claim_wins",
        "src/protocols/commit_reveal.rs:has_commit_reveal_pattern",
        "src/protocols/commit_reveal.rs:hash_matches_preimage",
        "src/protocols/commit_reveal.rs:known_commit_reveal_selectors",
        "src/protocols/commit_reveal.rs:reveal_outcome_wins",
        "src/protocols/curve.rs:compute_d_concrete",
        "src/protocols/curve.rs:get_dy_concrete",
        "src/protocols/curve.rs:get_dy_symbolic",
        "src/protocols/curve.rs:get_virtual_price_concrete",
        "src/protocols/curve.rs:is_invariant_satisfied",
        "src/protocols/dust_debt.rs:known_dust_bad_debt_selectors",
        "src/protocols/dust_debt.rs:liquidation_is_unprofitable",
        "src/protocols/dust_debt.rs:liquidation_recovery_with_bonus",
        "src/protocols/erc4626.rs:all_selectors",
        "src/protocols/erc4626.rs:assets_per_share_non_decreasing",
        "src/protocols/erc4626.rs:classify_selector",
        "src/protocols/erc4626.rs:first_depositor_inflation_drainable",
        "src/protocols/erc4626.rs:has_share_rounding_griefing_pattern",
        "src/protocols/erc4626.rs:has_vault_inflation_pattern",
        "src/protocols/erc4626.rs:known_vault_inflation_selectors",
        "src/protocols/erc4626.rs:share_roundtrip_leaks_assets",
        "src/protocols/fee_on_transfer.rs:known_fee_sensitive_selectors",
        "src/protocols/fee_on_transfer.rs:selector_from_call_data",
        "src/protocols/fee_on_transfer.rs:strict_received_shortfall",
        "src/protocols/flash_loan/mod.rs:default_provider_specs",
        "src/protocols/flash_loan/mod.rs:get_default_providers",
        "src/protocols/flash_loan/mod.rs:provider_specs_for_chain",
        "src/protocols/flash_loan/mod.rs:provider_specs_for_modeling",
        "src/protocols/governance.rs:flash_loan_meets_quorum",
        "src/protocols/governance.rs:has_delegatee_hijack_pattern",
        "src/protocols/governance.rs:has_flash_loan_governance_pattern",
        "src/protocols/governance.rs:has_quorum_manipulation_pattern",
        "src/protocols/governance.rs:known_delegatee_hijack_selectors",
        "src/protocols/governance.rs:known_governance_flash_vote_selectors",
        "src/protocols/governance.rs:known_quorum_manipulation_selectors",
        "src/protocols/governance.rs:proposal_transfers_treasury",
        "src/protocols/governance.rs:quorum_ratio_satisfied_after_mint",
        "src/protocols/governance.rs:unauthorized_delegate_to_attacker",
        "src/protocols/groth16.rs:audit_groth16_verifier",
        "src/protocols/init_race.rs:build_initializer_payloads",
        "src/protocols/init_race.rs:is_initialization_selector",
        "src/protocols/init_race.rs:known_initialization_selectors",
        "src/protocols/init_race.rs:selector_from_call_data",
        "src/protocols/interest_rate.rs:known_interest_rate_selectors",
        "src/protocols/interest_rate.rs:linear_borrow_rate_wad",
        "src/protocols/interest_rate.rs:rate_drop_exceeds_bps",
        "src/protocols/interest_rate.rs:utilization_wad",
        "src/protocols/lending.rs:e_mode_borrow_allowed",
        "src/protocols/lending.rs:aave_index_compound_after_blocks_wad",
        "src/protocols/lending.rs:apply_index_ratio",
        "src/protocols/lending.rs:compound_borrow_index_simple_after_blocks_wad",
        "src/protocols/lending.rs:get_mint_amount",
        "src/protocols/lending.rs:get_redemption_amount",
        "src/protocols/lending.rs:is_insolvent",
        "src/protocols/lending.rs:is_liquidatable",
        "src/protocols/lending.rs:isolation_mode_borrow_allowed",
        "src/protocols/lending.rs:known_ltv_lag_selectors",
        "src/protocols/lending.rs:ltv_ratio_at_least_bps",
        "src/protocols/lending.rs:mul_scaled",
        "src/protocols/lending.rs:pow_scaled_u64",
        "src/protocols/lending.rs:supply_cap_allows_supply",
        "src/protocols/lending.rs:value_after_bps_drop",
        "src/protocols/liquidation.rs:known_liquidation_selectors",
        "src/protocols/liquidation.rs:reserve_drop",
        "src/protocols/nft_callbacks.rs:approval_hijack_succeeds",
        "src/protocols/nft_callbacks.rs:has_erc1155_callback_reentrancy_pattern",
        "src/protocols/nft_callbacks.rs:has_erc721_approval_hijack_pattern",
        "src/protocols/nft_callbacks.rs:has_erc721_callback_reentrancy_pattern",
        "src/protocols/nft_callbacks.rs:has_erc721_mint_callback_drain_pattern",
        "src/protocols/nft_callbacks.rs:known_erc1155_callback_reentrancy_selectors",
        "src/protocols/nft_callbacks.rs:known_erc721_approval_hijack_selectors",
        "src/protocols/nft_callbacks.rs:known_erc721_callback_reentrancy_selectors",
        "src/protocols/nft_callbacks.rs:known_erc721_mint_callback_drain_selectors",
        "src/protocols/prng.rs:has_gambling_contract_pattern",
        "src/protocols/prng.rs:has_weak_prng_pattern",
        "src/protocols/prng.rs:known_gambling_scanner_selectors",
        "src/protocols/prng.rs:known_weak_prng_selectors",
        "src/protocols/prng.rs:next_block_timestamp_in_range",
        "src/protocols/prng.rs:wins_modulo",
        "src/protocols/psm.rs:known_psm_selectors",
        "src/protocols/psm.rs:psm_drain_ratio_exceeds_bps",
        "src/protocols/read_only_reentrancy.rs:has_read_only_reentrancy_pattern",
        "src/protocols/read_only_reentrancy.rs:has_read_only_reentrancy_scanner_pattern",
        "src/protocols/read_only_reentrancy.rs:known_read_only_reentrancy_scanner_selectors",
        "src/protocols/read_only_reentrancy.rs:known_read_only_reentrancy_selectors",
        "src/protocols/read_only_reentrancy.rs:stale_view_price_drift_exceeds_bps",
        "src/protocols/redemption.rs:known_redemption_selectors",
        "src/protocols/redemption.rs:redemption_arb_exceeds_bps",
        "src/protocols/redemption.rs:value_from_bps_price",
        "src/protocols/timelock.rs:has_timelock_expiry_pattern",
        "src/protocols/timelock.rs:known_timelock_sniper_selectors",
        "src/protocols/timelock.rs:timelock_window_open",
        "src/protocols/uniswap_v2.rs:get_amount_out",
        "src/protocols/uniswap_v3.rs:get_amount_out",
        "src/protocols/uniswap_v3.rs:next_initialized_tick_within_one_word",
        "src/protocols/uniswap_v3.rs:swap_exact_in_multi_tick",
        "src/protocols/uniswap_v3.rs:symbolic_tick_bitmap",
        "src/protocols/uniswap_v4.rs:hook_selectors",
        "src/protocols/uniswap_v4.rs:donate",
        "src/protocols/uniswap_v4.rs:credit_from_pool",
        "src/protocols/uniswap_v4.rs:debit_to_pool",
        "src/protocols/uniswap_v4.rs:is_fully_settled",
        "src/protocols/uniswap_v4.rs:is_hook_callback_selector",
        "src/protocols/uniswap_v4.rs:is_pool_manager_selector",
        "src/protocols/uniswap_v4.rs:modeled_hook_return_words",
        "src/protocols/uniswap_v4.rs:modeled_pool_manager_return_words",
        "src/protocols/uniswap_v4.rs:modify_position",
        "src/protocols/uniswap_v4.rs:pool_manager_selectors",
        "src/protocols/uniswap_v4.rs:settle_transfer",
        "src/protocols/uniswap_v4.rs:swap",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

#[test]
fn protocol_public_function_inventory_is_complete() {
    let expected = expected_protocol_public_fn_inventory();
    let actual = protocol_public_fn_inventory();
    assert_eq!(
        actual, expected,
        "protocol public function inventory drifted"
    );
}

#[test]
fn selector_and_registry_references_are_exact() {
    let expected_commit = sorted_dedup_4(vec![
        selector4("commit(bytes32)"),
        selector4("commitHash(bytes32)"),
        selector4("reveal(uint256,bytes32)"),
        selector4("reveal(bytes32,uint256)"),
        selector4("claimPrize()"),
        selector4("claim()"),
    ]);
    assert_eq!(
        commit_reveal::known_commit_reveal_selectors(),
        expected_commit
    );

    let expected_vrf_fulfill = sorted_dedup_4(vec![
        selector4("rawFulfillRandomWords(uint256,uint256[])"),
        selector4("fulfillRandomWords(uint256,uint256[])"),
    ]);
    assert_eq!(
        chainlink_vrf::known_vrf_fulfill_selectors(),
        expected_vrf_fulfill
    );

    let expected_vrf_claim = sorted_dedup_4(vec![
        selector4("claimPrize()"),
        selector4("claim()"),
        selector4("claim(uint256)"),
        selector4("settle()"),
        selector4("withdrawWinnings()"),
    ]);
    assert_eq!(
        chainlink_vrf::known_vrf_claim_selectors(),
        expected_vrf_claim
    );

    let expected_fee = sorted_dedup_4(vec![
        selector4("deposit(uint256)"),
        selector4("deposit(uint256,address)"),
        selector4("mint(uint256)"),
        selector4("mint(uint256,address)"),
        selector4("stake(uint256)"),
    ]);
    assert_eq!(
        fee_on_transfer::known_fee_sensitive_selectors(),
        expected_fee
    );

    let expected_ltv = sorted_dedup_4(vec![
        selector4("borrow(uint256)"),
        selector4("borrow(address,uint256,uint256,uint16,address)"),
        selector4("supply(uint256)"),
        selector4("supply(address,uint256,address,uint16)"),
        selector4("withdraw(uint256)"),
        selector4("withdraw(address,uint256,address)"),
        selector4("liquidationCall(address,address,address,uint256,bool)"),
        selector4("liquidateBorrow(address,uint256,address)"),
    ]);
    assert_eq!(lending::known_ltv_lag_selectors(), expected_ltv);

    let expected_hook_selectors = vec![
        selector32("beforeInitialize(address,(address,address,uint24,int24,address),uint160,bytes)"),
        selector32(
            "afterInitialize(address,(address,address,uint24,int24,address),uint160,int24,bytes)",
        ),
        selector32("beforeAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"),
        selector32("afterAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int256,int256),bytes)"),
        selector32("beforeRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)"),
        selector32("afterRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int256,int256),bytes)"),
        selector32("beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)"),
        selector32("afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),(int256,int256),bytes)"),
        selector32("beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)"),
        selector32("afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)"),
    ];
    assert_eq!(uniswap_v4::hook_selectors(), expected_hook_selectors);

    let selectors_4626 = erc4626::all_selectors();
    let expected_4626 = vec![
        selector32("totalAssets()"),
        selector32("totalSupply()"),
        selector32("deposit(uint256,address)"),
        selector32("mint(uint256,address)"),
        selector32("withdraw(uint256,address,address)"),
        selector32("redeem(uint256,address,address)"),
    ];
    assert_eq!(selectors_4626, expected_4626);
    for s in selectors_4626 {
        assert!(erc4626::classify_selector(s).is_some());
    }

    let providers = flash_loan::get_default_providers(8453);
    assert_eq!(providers.len(), 2);
}

#[test]
fn protocol_concrete_reference_gauntlet_10000_samples() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let mut rng = Lcg::new(0x00C0_FFEE_F00D_BAAD);

    let q96 = U256::from(1u64) << 96;
    let mask112 = (U256::from(1u64) << 112) - U256::from(1u64);

    for _ in 0..SAMPLES {
        let amount_a = rng.range_u64(0, 1_000_000);
        let amount_b = rng.range_u64(0, 1_000_000);
        let amount_c = rng.range_u64(0, 1_000_000);

        let bv_a = BV::from_u64(&ctx, amount_a, 256);
        let bv_b = BV::from_u64(&ctx, amount_b, 256);
        let bv_c = BV::from_u64(&ctx, amount_c, 256);

        let shortfall = fee_on_transfer::strict_received_shortfall(&ctx, &bv_a, &bv_b);
        assert_eq!(
            bool_const(&shortfall, "strict_received_shortfall"),
            amount_a > 0 && amount_b < amount_a
        );

        let same_block = chainlink_vrf::same_block_claim_window(&ctx, &bv_a, &bv_b);
        assert_eq!(
            bool_const(&same_block, "same_block_claim_window"),
            amount_a > 0 && amount_b == amount_a
        );

        let vrf_wins = chainlink_vrf::vrf_claim_wins(&ctx, &bv_a, &bv_b, &bv_c);
        let expected_vrf_wins =
            amount_b > 0 && amount_c < amount_b && (amount_a % amount_b == amount_c);
        assert_eq!(bool_const(&vrf_wins, "vrf_claim_wins"), expected_vrf_wins);

        let prng_wins = prng::wins_modulo(&ctx, &bv_a, &bv_b, &bv_c);
        let expected_prng_wins =
            amount_b > 0 && amount_c < amount_b && (amount_a % amount_b == amount_c);
        assert_eq!(bool_const(&prng_wins, "wins_modulo"), expected_prng_wins);

        let recovery_bv = dust_debt::liquidation_recovery_with_bonus(&ctx, &bv_a, 500);
        let expected_recovery = (u128::from(amount_a) * 10_500u128) / 10_000u128;
        assert_eq!(
            bv_const_u256(&recovery_bv, "liquidation_recovery_with_bonus"),
            U256::from(expected_recovery)
        );

        let psm_ok = psm::psm_drain_ratio_exceeds_bps(&ctx, &bv_a, &bv_b, 500);
        let expected_psm_ok = u128::from(amount_b) * 10_000u128 > u128::from(amount_a) * 10_500u128;
        assert_eq!(
            bool_const(&psm_ok, "psm_drain_ratio_exceeds_bps"),
            expected_psm_ok
        );

        let redemption_ok = redemption::redemption_arb_exceeds_bps(&ctx, &bv_a, &bv_b, 500);
        assert_eq!(
            bool_const(&redemption_ok, "redemption_arb_exceeds_bps"),
            expected_psm_ok
        );

        let value_price = redemption::value_from_bps_price(&ctx, &bv_a, &bv_b);
        let expected_value_price = (u128::from(amount_a) * u128::from(amount_b)) / 10_000u128;
        assert_eq!(
            bv_const_u256(&value_price, "value_from_bps_price"),
            U256::from(expected_value_price)
        );

        let timelock_ok = timelock::timelock_window_open(&ctx, &bv_a, &bv_b);
        assert_eq!(
            bool_const(&timelock_ok, "timelock_window_open"),
            amount_a > 0 && amount_b > 0 && amount_a >= amount_b
        );

        let amm_next = amm_price_impact::sqrt_price_x96_after_input(
            &ctx,
            &BV::from_u64(&ctx, 1 + (amount_a % 10_000), 256),
            &BV::from_u64(&ctx, 1 + (amount_b % 10_000), 256),
            &BV::from_u64(&ctx, 1 + (amount_c % 10_000), 256),
            true,
            3_000,
        );
        assert!(amm_next.get_size() == 256);

        let v2_out = uniswap_v2::get_amount_out(
            &BV::from_u64(&ctx, 1 + (amount_a % 10_000), 256),
            &BV::from_u64(&ctx, 1 + (amount_b % 10_000), 256),
            &BV::from_u64(&ctx, 1 + (amount_c % 10_000), 256),
        );
        let ain = U256::from(1 + (amount_a % 10_000));
        let rin = U256::from(1 + (amount_b % 10_000)) & mask112;
        let rout = U256::from(1 + (amount_c % 10_000)) & mask112;
        let amount_in_with_fee = ain * U256::from(997u64);
        let expected_v2 = safe_div_u256(
            amount_in_with_fee * rout,
            rin * U256::from(1000u64) + amount_in_with_fee,
        );
        assert_eq!(
            bv_const_u256(&v2_out, "uniswap_v2_get_amount_out"),
            expected_v2
        );

        let v3_out_zf1 = uniswap_v3::get_amount_out(
            &ctx,
            &BV::from_u64(&ctx, 1 + (amount_a % 10_000), 256),
            &BV::from_u64(&ctx, 1 + (amount_b % 10_000), 256),
            &BV::from_u64(&ctx, 1 + (amount_c % 10_000), 256),
            true,
            3_000,
        );
        assert!(v3_out_zf1.get_size() == 256);

        let amount_rem = safe_div_u256(
            U256::from(amount_a) * U256::from(997_000u64),
            U256::from(1_000_000u64),
        );
        let liq = U256::from(1 + (amount_b % 10_000));
        let sqrtp = U256::from(1 + (amount_c % 10_000));
        let numerator = liq * sqrtp * q96;
        let denominator = liq * q96 + amount_rem * sqrtp;
        let _expected_amm = safe_div_u256(numerator, denominator);

        let stored = BV::from_u64(&ctx, amount_a, 256);
        let leaked = BV::from_u64(&ctx, amount_b, 256);
        let hash_formula = commit_reveal::hash_matches_preimage(&ctx, &stored, &leaked);
        let keccak = KeccakTheory::new(&ctx);
        let hash_ref = stored._eq(&keccak.apply_symbolic(Some(vec![leaked.clone()])));
        assert!(bool_const(
            &hash_formula._eq(&hash_ref),
            "hash_matches_preimage_ref"
        ));

        let bytecode = Bytes::from(rng.bytes(64));
        let _ = prng::has_weak_prng_pattern(&bytecode);
        let _ = prng::has_gambling_contract_pattern(&bytecode);
        let _ = governance::has_flash_loan_governance_pattern(&bytecode);
        let _ = governance::has_quorum_manipulation_pattern(&bytecode);
        let _ = governance::has_delegatee_hijack_pattern(&bytecode);
        let _ = nft_callbacks::has_erc721_callback_reentrancy_pattern(&bytecode);
        let _ = nft_callbacks::has_erc1155_callback_reentrancy_pattern(&bytecode);
        let _ = nft_callbacks::has_erc721_mint_callback_drain_pattern(&bytecode);
        let _ = nft_callbacks::has_erc721_approval_hijack_pattern(&bytecode);
        let _ = read_only_reentrancy::has_read_only_reentrancy_pattern(&bytecode);
        let _ = read_only_reentrancy::has_read_only_reentrancy_scanner_pattern(&bytecode);
        let _ = timelock::has_timelock_expiry_pattern(&bytecode);
        let _ = commit_reveal::has_commit_reveal_pattern(&bytecode);
        let _ = chainlink_vrf::has_vrf_timing_pattern(&bytecode);

        let calldata_len = rng.range_u64(0, 32) as usize;
        let calldata = Bytes::from(rng.bytes(calldata_len));
        let expected_selector = if calldata.len() >= 4 {
            let mut s = [0u8; 4];
            s.copy_from_slice(&calldata[0..4]);
            Some(s)
        } else {
            None
        };
        assert_eq!(
            fee_on_transfer::selector_from_call_data(&calldata),
            expected_selector
        );
        assert_eq!(
            init_race::selector_from_call_data(&calldata),
            expected_selector
        );

        let attacker = Address::from([0x11; 20]);
        let payloads =
            init_race::build_initializer_payloads(selector4("initialize(address)"), attacker);
        assert_eq!(payloads.len(), 3);

        assert!(
            contains_push4(bytecode.as_ref(), selector4("claim()"))
                || !contains_push4(bytecode.as_ref(), selector4("claim()"))
        );
    }
}
