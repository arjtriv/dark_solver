impl ExploitObjective for PsmDrainingObjective {
    fn name(&self) -> &str {
        "Peg Stability Module Depletion Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "psm_drain_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> = crate::protocols::psm::known_psm_selectors()
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
            selectors.truncate(selectors.len().min(8));

            for call_data in &selectors {
                let trace = execute_psm_trace(solver, &mut scenario, call_data);
                if has_psm_drain_signal(
                    ctx,
                    solver,
                    scenario.attacker,
                    scenario.contract_addr,
                    self.min_gain_bps,
                    &trace,
                ) {
                    return Some(ExploitParams {
                        flash_loan_amount: U256::ZERO,
                        flash_loan_token: Address::ZERO,
                        flash_loan_provider: Address::ZERO,
                                               flash_loan_legs: Vec::new(),
                        steps: vec![ExploitStep {
                            target: scenario.contract_addr,
                            call_data: call_data.clone(),
                            execute_if: None,
                        }],
                        expected_profit: Some(U256::from(1u64)),
                        block_offsets: None,
                    });
                }
            }

            None
        })
    }
}

#[derive(Clone)]
struct LiquidationSpiralSlotDelta<'ctx> {
    pre_value: BV<'ctx>,
    post_value: BV<'ctx>,
}

#[derive(Clone)]
struct LiquidationSpiralTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    slot_deltas: Vec<LiquidationSpiralSlotDelta<'ctx>>,
}

fn reserve_drop_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    pre_value: &BV<'ctx>,
    post_value: &BV<'ctx>,
    min_drop_bps: u64,
) -> Bool<'ctx> {
    let scale = crate::symbolic::utils::math::extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let threshold = crate::symbolic::utils::math::extend_to_512(
        ctx,
        &BV::from_u64(ctx, 10_000u64.saturating_sub(min_drop_bps), 256),
    );
    let pre_512 = crate::symbolic::utils::math::extend_to_512(ctx, pre_value);
    let post_512 = crate::symbolic::utils::math::extend_to_512(ctx, post_value);

    post_512.bvmul(&scale).bvult(&pre_512.bvmul(&threshold))
}

const LIQUIDATION_SPIRAL_MAX_SLOTS: usize = 3;

fn execute_liquidation_spiral_trace<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> LiquidationSpiralTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    let pre_storage = scenario
        .machine
        .storage
        .get(&scenario.contract_addr)
        .cloned()
        .unwrap_or_else(|| scenario.machine.zero_storage());

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.storage_log.clear();

    let result;
    {
        let mut evm = Evm::builder()
            .with_db(&mut current_db)
            .with_external_context(&mut scenario.machine)
            .append_handler_register(revm::inspector_handle_register)
            .modify_tx_env(|tx| {
                tx.caller = scenario.attacker;
                tx.transact_to = TransactTo::Call(scenario.contract_addr);
                tx.data = call_data.clone();
                tx.value = U256::ZERO;
                tx.gas_limit = 10_000_000;
            })
            .build();
        result = evm.transact_commit();
    }

    let success_execution = if let Ok(res) = result {
        matches!(res, revm::primitives::ExecutionResult::Success { .. })
    } else {
        false
    };

    let mut slot_deltas = Vec::new();
    for (key, _) in scenario
        .machine
        .storage_log
        .iter()
        .take(LIQUIDATION_SPIRAL_MAX_SLOTS)
    {
        let pre_value = pre_storage
            .select(key)
            .as_bv()
            .unwrap_or_else(|| crate::symbolic::utils::math::zero(ctx));
        let post_value = scenario
            .machine
            .storage
            .get(&scenario.contract_addr)
            .and_then(|arr| arr.select(key).as_bv())
            .unwrap_or_else(|| crate::symbolic::utils::math::zero(ctx));
        slot_deltas.push(LiquidationSpiralSlotDelta {
            pre_value,
            post_value,
        });
    }

    let trace = LiquidationSpiralTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        slot_deltas,
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_liquidation_spiral_drop<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    min_drop_bps: u64,
    trace: &LiquidationSpiralTrace<'ctx>,
) -> bool {
    if trace.reverted || !trace.success_execution {
        return false;
    }

    for delta in &trace.slot_deltas {
        solver.push();
        solver.assert(&reserve_drop_exceeds_bps(
            ctx,
            &delta.pre_value,
            &delta.post_value,
            min_drop_bps,
        ));
        let sat = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if sat {
            return true;
        }
    }

    false
}

/// Strategy 9: Liquidation Cascade Risk (Death Spiral)
/// Flags reserve drops across mutated slots indicative of insolvency cascades.
pub struct LiquidationSpiralObjective {
    pub rpc_url: String,
    pub min_drop_bps: u64,
}

impl ExploitObjective for LiquidationSpiralObjective {
    fn name(&self) -> &str {
        "Liquidation Cascade Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "liquidation_spiral_loan",
            )
            .ok()?;

            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(8));

            for call_data in &selectors {
                let trace = execute_liquidation_spiral_trace(ctx, solver, &mut scenario, call_data);
                if has_liquidation_spiral_drop(ctx, solver, self.min_drop_bps, &trace) {
                    return Some(ExploitParams {
                        flash_loan_amount: U256::ZERO,
                        flash_loan_token: Address::ZERO,
                        flash_loan_provider: Address::ZERO,
                                               flash_loan_legs: Vec::new(),
                        steps: vec![ExploitStep {
                            target: scenario.contract_addr,
                            call_data: call_data.clone(),
                            execute_if: None,
                        }],
                        expected_profit: Some(U256::from(1u64)),
                        block_offsets: None,
                    });
                }
            }

            None
        })
    }
}

fn build_block_offsets(steps_len: usize) -> Option<Vec<u64>> {
    if steps_len < 2 {
        return None;
    }
    Some((0..steps_len as u64).collect())
}

fn discover_oracle_deps<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    selectors: &[Bytes],
) -> Vec<OracleDep> {
    let snapshot = scenario.machine.snapshot();
    let mut deps = Vec::new();

    for call_data in selectors {
        let mut current_db = scenario.db.clone();
        solver.push();

        scenario.machine.reset_calldata();
        scenario.machine.tx_id += 1;
        scenario.machine.reverted = false;
        scenario.machine.oracle_deps.clear();

        {
            let mut evm = Evm::builder()
                .with_db(&mut current_db)
                .with_external_context(&mut scenario.machine)
                .append_handler_register(revm::inspector_handle_register)
                .modify_tx_env(|tx| {
                    tx.caller = scenario.attacker;
                    tx.transact_to = TransactTo::Call(scenario.contract_addr);
                    tx.data = call_data.clone();
                    tx.value = U256::ZERO;
                    tx.gas_limit = 10_000_000;
                })
                .build();
            let _ = evm.transact_commit();
        }

        deps.extend(scenario.machine.oracle_deps.clone());
        scenario.machine.restore(&snapshot);
        solver.pop(1);
    }

    deps
}

/// Strategy 10: TWAP Oracle Deviation Risk (Multi-Block)
/// Solves a multi-step path and schedules it across successive blocks when oracle deps are present.
pub struct TwapOracleManipulationObjective {
    pub rpc_url: String,
    pub chain_id: u64,
}

impl ExploitObjective for TwapOracleManipulationObjective {
    fn name(&self) -> &str {
        "TWAP Oracle Deviation Risk (Multi-Block)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "twap_oracle_loan",
            )
            .ok()?;

            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(8));

            let deps = discover_oracle_deps(solver, &mut scenario, &selectors);
            let (oracle_pairs, chainlink_feeds) = collect_oracle_sources(&deps);
            if oracle_pairs.is_empty() && chainlink_feeds.is_empty() {
                return None;
            }

            scenario.constrain_loan(solver, "1000000000000000000000000");
            let initial_token_vars = scenario.init_tokens(self.chain_id, bytecode);

            let mut params = solve_market_invariant(
                ctx,
                solver,
                &mut scenario.machine,
                scenario.db,
                &scenario.flash_loan_amount,
                &scenario.flash_loan_parts,
                scenario.attacker,
                scenario.contract_addr,
                0,
                2,
                &selectors,
                &initial_token_vars,
            )?;

            let offsets = build_block_offsets(params.steps.len())?;
            params.block_offsets = Some(offsets);
            Some(params)
        })
    }
}

fn build_interest_rate_gaming_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

/// Strategy 11: Interest Rate Model Drift Risk (Utilization Spike)
/// Models flash-deposit utilization crash, cheap borrow, and post-withdraw insolvency.
pub struct InterestRateModelGamingObjective {
    pub rpc_url: String,
    pub min_rate_drop_bps: u64,
}

impl ExploitObjective for InterestRateModelGamingObjective {
    fn name(&self) -> &str {
        "Interest Rate Model Drift Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "interest_rate_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::interest_rate::known_interest_rate_selectors()
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

            let total_borrows = BV::new_const(ctx, "ir_total_borrows", 256);
            let total_supply_before = BV::new_const(ctx, "ir_total_supply_before", 256);
            let shock_deposit = BV::new_const(ctx, "ir_shock_deposit", 256);
            let cheap_borrow = BV::new_const(ctx, "ir_cheap_borrow", 256);
            let withdraw_amount = BV::new_const(ctx, "ir_withdraw_amount", 256);
            let base_rate = BV::new_const(ctx, "ir_base_rate", 256);
            let slope = BV::new_const(ctx, "ir_slope", 256);
            let collateral_value = BV::new_const(ctx, "ir_collateral_value", 256);

            let zero = crate::symbolic::utils::math::zero(ctx);
            solver.assert(&total_borrows.bvugt(&zero));
            solver.assert(&total_supply_before.bvugt(&zero));
            solver.assert(&total_borrows.bvule(&total_supply_before));
            solver.assert(&shock_deposit.bvugt(&zero));
            solver.assert(&cheap_borrow.bvugt(&zero));
            solver.assert(&base_rate.bvugt(&zero));
            solver.assert(&slope.bvugt(&zero));
            solver.assert(&collateral_value.bvugt(&zero));

            // Utilization before shock: >= 80%
            let util_before = crate::protocols::interest_rate::utilization_wad(
                ctx,
                &total_borrows,
                &total_supply_before,
            );
            let wad = crate::symbolic::utils::math::wad(ctx);
            let eighty_pct = wad
                .bvmul(&BV::from_u64(ctx, 80, 256))
                .bvudiv(&BV::from_u64(ctx, 100, 256));
            solver.assert(&util_before.bvuge(&eighty_pct));

            let supply_after = total_supply_before.bvadd(&shock_deposit);
            solver.assert(&supply_after.bvuge(&total_supply_before));
            let util_after_deposit = crate::protocols::interest_rate::utilization_wad(
                ctx,
                &total_borrows,
                &supply_after,
            );
            let one_pct = wad
                .bvmul(&BV::from_u64(ctx, 1, 256))
                .bvudiv(&BV::from_u64(ctx, 100, 256));
            solver.assert(&util_after_deposit.bvule(&one_pct));

            let rate_before = crate::protocols::interest_rate::linear_borrow_rate_wad(
                ctx,
                &base_rate,
                &slope,
                &util_before,
            );
            let rate_after = crate::protocols::interest_rate::linear_borrow_rate_wad(
                ctx,
                &base_rate,
                &slope,
                &util_after_deposit,
            );
            solver.assert(&crate::protocols::interest_rate::rate_drop_exceeds_bps(
                ctx,
                &rate_before,
                &rate_after,
                self.min_rate_drop_bps,
            ));

            let borrows_after = total_borrows.bvadd(&cheap_borrow);
            solver.assert(&borrows_after.bvuge(&total_borrows));
            solver.assert(&withdraw_amount.bvuge(&shock_deposit));
            solver.assert(&withdraw_amount.bvule(&supply_after));
            let supply_final = supply_after.bvsub(&withdraw_amount);
            solver.assert(&supply_final.bvugt(&zero));

            let util_after_withdraw = crate::protocols::interest_rate::utilization_wad(
                ctx,
                &borrows_after,
                &supply_final,
            );
            solver.assert(&util_after_withdraw.bvugt(&util_after_deposit));
            solver.assert(&crate::protocols::lending::is_insolvent(
                ctx,
                &collateral_value,
                &borrows_after,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                               flash_loan_legs: Vec::new(),
                steps: build_interest_rate_gaming_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_collateral_factor_ltv_lag_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

fn collateral_factor_lag_violation<'ctx>(
    ctx: &'ctx Context,
    collateral_before: &BV<'ctx>,
    debt_after: &BV<'ctx>,
    collateral_factor_bps: u64,
    min_pre_ltv_bps: u64,
    shock_drop_bps: u64,
) -> Bool<'ctx> {
    let precision = BV::from_u64(ctx, 10_000, 256);
    let capped_factor = collateral_factor_bps.min(10_000);
    let pre_ltv_gate = min_pre_ltv_bps.min(capped_factor);
    let factor = BV::from_u64(ctx, capped_factor, 256);

    let stale_oracle_safe = crate::protocols::lending::is_liquidatable(
        ctx,
        collateral_before,
        debt_after,
        &factor,
        &precision,
    )
    .not();
    let near_max_ltv = crate::protocols::lending::ltv_ratio_at_least_bps(
        ctx,
        collateral_before,
        debt_after,
        pre_ltv_gate,
        &precision,
    );

    let collateral_after_shock =
        crate::protocols::lending::value_after_bps_drop(ctx, collateral_before, shock_drop_bps);
    let shock_observed = collateral_after_shock.bvult(collateral_before);
    let actually_liquidatable = crate::protocols::lending::is_liquidatable(
        ctx,
        &collateral_after_shock,
        debt_after,
        &factor,
        &precision,
    );
    let insolvent =
        crate::protocols::lending::is_insolvent(ctx, &collateral_after_shock, debt_after);

    Bool::and(
        ctx,
        &[
            &near_max_ltv,
            &stale_oracle_safe,
            &shock_observed,
            &actually_liquidatable,
            &insolvent,
        ],
    )
}

/// Strategy 12: Collateral Factor (LTV) Update-Lag Risk
/// Models borrow-at-cap under stale collateral pricing, then insolvency after volatility shock.
pub struct CollateralFactorLtvLagObjective {
    pub rpc_url: String,
    pub collateral_factor_bps: u64,
    pub min_pre_ltv_bps: u64,
    pub shock_drop_bps: u64,
}

impl ExploitObjective for CollateralFactorLtvLagObjective {
    fn name(&self) -> &str {
        "Collateral Factor (LTV) Update-Lag Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "ltv_lag_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> = crate::protocols::lending::known_ltv_lag_selectors()
                .iter()
                .map(|selector| Bytes::copy_from_slice(selector))
                .collect();
            selectors.extend(
                crate::protocols::liquidation::known_liquidation_selectors()
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

            let collateral_before = BV::new_const(ctx, "ltv_collateral_before", 256);
            let debt_before = BV::new_const(ctx, "ltv_debt_before", 256);
            let borrow_delta = BV::new_const(ctx, "ltv_borrow_delta", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);

            solver.assert(&collateral_before.bvugt(&zero));
            solver.assert(&debt_before.bvuge(&zero));
            solver.assert(&borrow_delta.bvugt(&zero));

            let debt_after = debt_before.bvadd(&borrow_delta);
            solver.assert(&debt_after.bvuge(&debt_before));
            solver.assert(&collateral_factor_lag_violation(
                ctx,
                &collateral_before,
                &debt_after,
                self.collateral_factor_bps,
                self.min_pre_ltv_bps,
                self.shock_drop_bps,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                               flash_loan_legs: Vec::new(),
                steps: build_collateral_factor_ltv_lag_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_redemption_arbitrage_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

/// Strategy 13: Redemption Pricing Dislocation Risk
/// Models buy-below-peg then treasury redemption-above-market while treasury reserves deplete.
pub struct RedemptionArbitrageObjective {
    pub rpc_url: String,
    pub min_gain_bps: u64,
}

impl ExploitObjective for RedemptionArbitrageObjective {
    fn name(&self) -> &str {
        "Redemption Pricing Dislocation Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "redemption_arb_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::redemption::known_redemption_selectors()
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

            let market_price_bps = BV::new_const(ctx, "redemption_market_price_bps", 256);
            let redeem_price_bps = BV::new_const(ctx, "redemption_redeem_price_bps", 256);
            let loop_units = BV::new_const(ctx, "redemption_loop_units", 256);
            let treasury_before = BV::new_const(ctx, "redemption_treasury_before", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);
            let min_price = BV::from_u64(ctx, 9000, 256);
            let max_price = BV::from_u64(ctx, 10_000, 256);
            let max_units = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(10u64).pow(U256::from(24u64)),
            );

            solver.assert(&market_price_bps.bvuge(&min_price));
            solver.assert(&market_price_bps.bvule(&max_price));
            solver.assert(&redeem_price_bps.bvuge(&min_price));
            solver.assert(&redeem_price_bps.bvule(&max_price));
            solver.assert(&redeem_price_bps.bvugt(&market_price_bps));
            solver.assert(&loop_units.bvugt(&zero));
            solver.assert(&loop_units.bvule(&max_units));
            solver.assert(&treasury_before.bvugt(&zero));

            let market_cost = crate::protocols::redemption::value_from_bps_price(
                ctx,
                &loop_units,
                &market_price_bps,
            );
            let redemption_out = crate::protocols::redemption::value_from_bps_price(
                ctx,
                &loop_units,
                &redeem_price_bps,
            );
            solver.assert(&market_cost.bvugt(&zero));
            solver.assert(&redemption_out.bvugt(&market_cost));
            solver.assert(&crate::protocols::redemption::redemption_arb_exceeds_bps(
                ctx,
                &market_cost,
                &redemption_out,
                self.min_gain_bps,
            ));

            solver.assert(&treasury_before.bvuge(&redemption_out));
            let treasury_after = treasury_before.bvsub(&redemption_out);
            solver.assert(&treasury_after.bvult(&treasury_before));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                               flash_loan_legs: Vec::new(),
                steps: build_redemption_arbitrage_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_dust_bad_debt_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

/// Strategy 14: Dust Bad-Debt Accumulation Risk
/// Models many small debt positions where liquidation cost dominates recoverable value.
pub struct DustBadDebtCreationObjective {
    pub rpc_url: String,
    pub max_dust_debt: U256,
    pub min_position_count: u64,
    pub liquidation_bonus_bps: u64,
}

impl ExploitObjective for DustBadDebtCreationObjective {
    fn name(&self) -> &str {
        "Dust Bad-Debt Accumulation Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "dust_bad_debt_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::dust_debt::known_dust_bad_debt_selectors()
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

            let position_count = BV::new_const(ctx, "dust_position_count", 256);
            let per_position_debt = BV::new_const(ctx, "dust_per_position_debt", 256);
            let liquidation_gas_cost = BV::new_const(ctx, "dust_liquidation_gas_cost", 256);
            let zero = crate::symbolic::utils::math::zero(ctx);
            let min_count = BV::from_u64(ctx, self.min_position_count.max(1), 256);
            let max_count = BV::from_u64(ctx, 20_000, 256);
            let max_dust_debt = crate::symbolic::z3_ext::bv_from_u256(ctx, self.max_dust_debt);

            solver.assert(&position_count.bvuge(&min_count));
            solver.assert(&position_count.bvule(&max_count));
            solver.assert(&per_position_debt.bvugt(&zero));
            solver.assert(&per_position_debt.bvule(&max_dust_debt));
            solver.assert(&liquidation_gas_cost.bvugt(&zero));
            solver.assert(&crate::protocols::dust_debt::liquidation_is_unprofitable(
                ctx,
                &per_position_debt,
                &liquidation_gas_cost,
                self.liquidation_bonus_bps,
            ));

            let total_bad_debt_512 =
                crate::symbolic::utils::math::extend_to_512(ctx, &per_position_debt).bvmul(
                    &crate::symbolic::utils::math::extend_to_512(ctx, &position_count),
                );
            let recovery_per_position =
                crate::protocols::dust_debt::liquidation_recovery_with_bonus(
                    ctx,
                    &per_position_debt,
                    self.liquidation_bonus_bps,
                );
            let total_recovery_512 =
                crate::symbolic::utils::math::extend_to_512(ctx, &recovery_per_position).bvmul(
                    &crate::symbolic::utils::math::extend_to_512(ctx, &position_count),
                );
            let total_cleanup_cost_512 =
                crate::symbolic::utils::math::extend_to_512(ctx, &liquidation_gas_cost).bvmul(
                    &crate::symbolic::utils::math::extend_to_512(ctx, &position_count),
                );

            solver.assert(&total_cleanup_cost_512.bvugt(&total_recovery_512));
            let min_total_bad_debt = if let Some(v) = self
                .max_dust_debt
                .checked_mul(U256::from(self.min_position_count.max(1)))
            {
                v
            } else {
                U256::MAX
            };
            let min_total_bad_debt_512 = crate::symbolic::utils::math::extend_to_512(
                ctx,
                &crate::symbolic::z3_ext::bv_from_u256(ctx, min_total_bad_debt),
            );
            solver.assert(&total_bad_debt_512.bvuge(&min_total_bad_debt_512));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                               flash_loan_legs: Vec::new(),
                steps: build_dust_bad_debt_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_amm_price_impact_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

fn has_selector(selectors: &[Bytes], selector: [u8; 4]) -> bool {
    selectors.iter().any(|sig| sig.as_ref() == selector)
}

fn build_atomic_arbitrage_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
    let mut steps = Vec::new();
    // Prefer a UniV2 swap selector then a UniV3 exactInput selector.
    let v2_swap = [0x02, 0x2c, 0x0d, 0x9f]; // swap(uint256,uint256,address,bytes)
    let v3_exact_input = [0xb8, 0x58, 0x18, 0x3f]; // exactInput((bytes,address,uint256,uint256,uint256))
    if has_selector(selectors, v2_swap) {
        steps.push(ExploitStep {
            target,
            call_data: Bytes::copy_from_slice(&v2_swap),
            execute_if: None,
        });
    }
    if has_selector(selectors, v3_exact_input) {
        steps.push(ExploitStep {
            target,
            call_data: Bytes::copy_from_slice(&v3_exact_input),
            execute_if: None,
        });
    }
    if steps.is_empty() {
        steps.push(ExploitStep {
            target,
            call_data: Bytes::new(),
            execute_if: None,
        });
    }
    steps
}

/// Strategy: Atomic Arbitrage (UniV2 vs UniV3 spread)
pub struct AtomicArbitrageObjective {
    pub rpc_url: String,
    pub min_spread_bps: u64,
}

impl ExploitObjective for AtomicArbitrageObjective {
    fn name(&self) -> &str {
        "Cross-AMM Price Dislocation (UniV2 vs UniV3)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "atomic_arb_loan",
            )
            .ok()?;

            let selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            let has_v2_surface = has_selector(&selectors, [0x02, 0x2c, 0x0d, 0x9f])
                || has_selector(&selectors, [0x09, 0x02, 0xf1, 0xac]); // getReserves()
            let has_v3_surface = has_selector(&selectors, [0xb8, 0x58, 0x18, 0x3f])
                || has_selector(&selectors, [0x41, 0x4b, 0xf3, 0x89]); // exactInputSingle
            if !(has_v2_surface && has_v3_surface) {
                return None;
            }

            let price_v2 = BV::new_const(ctx, "atomic_arb_price_v2", 256);
            let price_v3 = BV::new_const(ctx, "atomic_arb_price_v3", 256);
            let one = BV::from_u64(ctx, 1, 256);
            let zero = crate::symbolic::utils::math::zero(ctx);
            solver.assert(&price_v2.bvugt(&zero));
            solver.assert(&price_v3.bvugt(&zero));

            let spread_a = ratio_gap_exceeds_bps(
                ctx,
                &price_v2,
                &one,
                &price_v3,
                &one,
                self.min_spread_bps,
            );
            let spread_b = ratio_gap_exceeds_bps(
                ctx,
                &price_v3,
                &one,
                &price_v2,
                &one,
                self.min_spread_bps,
            );
            solver.assert(&Bool::or(ctx, &[&spread_a, &spread_b]));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_atomic_arbitrage_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

/// Strategy 15: AMM Price Impact (Slippage) Modeling
/// Models UniV3 depth-driven impact and requires attack cost to be strictly below liquidation profit.
pub struct AmmPriceImpactObjective {
    pub rpc_url: String,
    pub min_price_impact_bps: u64,
    pub fee_pips: u64,
}
