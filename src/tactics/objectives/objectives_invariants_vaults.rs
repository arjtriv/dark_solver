impl ExploitObjective for TaintFlowStorageCorruptionObjective {
    fn name(&self) -> &str {
        "Taint-Flow Storage Corruption"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|_ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                _ctx,
                solver,
                &rpc_url,
                bytecode,
                "taint_flow_loan",
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
                let trace = execute_taint_flow_trace(solver, &mut scenario, call_data);
                if trace.reverted || !trace.success_execution {
                    continue;
                }

                let has_guard = trace_has_jumpi_guard(bytecode, &trace.visited_pcs);
                if has_guard {
                    continue;
                }

                let tainted_key_write = trace
                    .storage_writes
                    .iter()
                    .any(|(key, _)| key_depends_on_user_input(key));

                if tainted_key_write {
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
struct PolynomialInvariantTrace<'ctx> {
    call_data: Bytes,
    success_execution: bool,
    reverted: bool,
    slot_a: BV<'ctx>,
    slot_b: BV<'ctx>,
    abstract_constraints: Vec<Bool<'ctx>>,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
    k_before: BV<'ctx>,
    k_after: BV<'ctx>,
}

const POLYNOMIAL_SLOT_RANGE_UPPER_BOUND: u64 = 63;
const POLYNOMIAL_SLOT_MIN_LIQUIDITY: u64 = 1;

fn read_storage_slot_word_at<'ctx>(
    machine: &SymbolicMachine<'ctx>,
    contract: Address,
    slot: &BV<'ctx>,
) -> BV<'ctx> {
    machine
        .storage
        .get(&contract)
        .and_then(|arr| arr.select(slot).as_bv())
        .unwrap_or_else(|| crate::symbolic::utils::math::zero(machine.context))
}

fn build_abstract_slot_pair_constraints<'ctx>(
    ctx: &'ctx Context,
    slot_a: &BV<'ctx>,
    slot_b: &BV<'ctx>,
) -> Vec<Bool<'ctx>> {
    let max_slot =
        crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(POLYNOMIAL_SLOT_RANGE_UPPER_BOUND));
    vec![
        slot_a._eq(slot_b).not(),
        slot_a.bvule(&max_slot),
        slot_b.bvule(&max_slot),
    ]
}

fn selected_slot_touched_constraint<'ctx>(
    ctx: &'ctx Context,
    storage_writes: &[(BV<'ctx>, BV<'ctx>)],
    slot: &BV<'ctx>,
) -> Option<Bool<'ctx>> {
    let constraints = storage_writes
        .iter()
        .map(|(write_slot, _)| write_slot._eq(slot))
        .collect::<Vec<_>>();
    if constraints.is_empty() {
        return None;
    }
    let refs = constraints.iter().collect::<Vec<_>>();
    Some(Bool::or(ctx, &refs))
}

fn execute_polynomial_invariant_trace<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> PolynomialInvariantTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    let slot_a = BV::new_const(ctx, format!("polynomial_slot_a_{}", scenario.machine.tx_id), 256);
    let slot_b = BV::new_const(ctx, format!("polynomial_slot_b_{}", scenario.machine.tx_id), 256);
    let mut abstract_constraints = build_abstract_slot_pair_constraints(ctx, &slot_a, &slot_b);

    let pre_x = read_storage_slot_word_at(&scenario.machine, scenario.contract_addr, &slot_a);
    let pre_y = read_storage_slot_word_at(&scenario.machine, scenario.contract_addr, &slot_b);
    let min_liquidity =
        crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(POLYNOMIAL_SLOT_MIN_LIQUIDITY));
    abstract_constraints.push(pre_x.bvuge(&min_liquidity));
    abstract_constraints.push(pre_y.bvuge(&min_liquidity));
    for constraint in &abstract_constraints {
        solver.assert(constraint);
    }

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

    let post_x = read_storage_slot_word_at(&scenario.machine, scenario.contract_addr, &slot_a);
    let post_y = read_storage_slot_word_at(&scenario.machine, scenario.contract_addr, &slot_b);

    let k_before = crate::symbolic::utils::math::extend_to_512(ctx, &pre_x)
        .bvmul(&crate::symbolic::utils::math::extend_to_512(ctx, &pre_y));
    let k_after = crate::symbolic::utils::math::extend_to_512(ctx, &post_x)
        .bvmul(&crate::symbolic::utils::math::extend_to_512(ctx, &post_y));

    let trace = PolynomialInvariantTrace {
        call_data: call_data.clone(),
        success_execution,
        reverted: scenario.machine.reverted,
        slot_a,
        slot_b,
        abstract_constraints,
        storage_writes: scenario.machine.storage_log.clone(),
        k_before,
        k_after,
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_polynomial_invariant_violation<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    trace: &PolynomialInvariantTrace<'ctx>,
) -> bool {
    let Some(touched_slot_a) =
        selected_slot_touched_constraint(ctx, &trace.storage_writes, &trace.slot_a)
    else {
        return false;
    };
    let Some(touched_slot_b) =
        selected_slot_touched_constraint(ctx, &trace.storage_writes, &trace.slot_b)
    else {
        return false;
    };
    solver.push();
    for constraint in &trace.abstract_constraints {
        solver.assert(constraint);
    }
    solver.assert(&touched_slot_a);
    solver.assert(&touched_slot_b);
    solver.assert(&trace.k_after.bvult(&trace.k_before));
    let sat = solver.check() == z3::SatResult::Sat;
    solver.pop(1);
    sat
}

/// Strategy 12: Polynomial Invariant Solver
/// Derives baseline x*y polynomial over a bounded symbolic slot pair and
/// flags satisfiable post-state drops that survive abstract slot constraints.
pub struct PolynomialInvariantObjective {
    pub rpc_url: String,
}

impl ExploitObjective for PolynomialInvariantObjective {
    fn name(&self) -> &str {
        "Polynomial Invariant Solver"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "polynomial_invariant_loan",
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
                let trace =
                    execute_polynomial_invariant_trace(ctx, solver, &mut scenario, call_data);
                if trace.reverted || !trace.success_execution {
                    continue;
                }

                if has_polynomial_invariant_violation(ctx, solver, &trace) {
                    return Some(ExploitParams {
                        flash_loan_amount: U256::ZERO,
                        flash_loan_token: Address::ZERO,
                        flash_loan_provider: Address::ZERO,
                        flash_loan_legs: Vec::new(),
                        steps: vec![ExploitStep {
                            target: scenario.contract_addr,
                            call_data: trace.call_data,
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

fn enforce_composite_risk_with_market_solver(
    rpc_url: &str,
    chain_id: u64,
    bytecode: &Bytes,
    anomaly_seed: &ExploitParams,
) -> Option<ExploitParams> {
    if anomaly_seed.steps.is_empty() {
        return None;
    }

    let mut selectors = anomaly_seed
        .steps
        .iter()
        .map(|step| step.call_data.clone())
        .collect::<Vec<_>>();
    selectors.sort();
    selectors.dedup();
    if selectors.is_empty() {
        return None;
    }

    run_with_z3_solver(|ctx, solver| {
        let mut scenario = crate::solver::setup::StandardScenario::try_new(
            ctx,
            solver,
            rpc_url,
            bytecode,
            "composite_risk_loan",
        )
        .ok()?;
        scenario.constrain_loan(solver, "1000000000000000000000000");
        let initial_token_vars = scenario.init_tokens(chain_id, bytecode);

        solve_market_invariant(
            ctx,
            solver,
            &mut scenario.machine,
            scenario.db,
            &scenario.flash_loan_amount,
            &scenario.flash_loan_parts,
            scenario.attacker,
            scenario.contract_addr,
            0,
            3,
            &selectors,
            &initial_token_vars,
        )
    })
}

/// Strategy 13: Composite High-Confidence Risk Synthesizer
/// Feeds anomaly discoveries into profit/corruption-constrained market solve and discards non-exploits.
pub struct CompositeRiskSynthesisObjective {
    pub rpc_url: String,
    pub chain_id: u64,
}

impl ExploitObjective for CompositeRiskSynthesisObjective {
    fn name(&self) -> &str {
        "Composite High-Confidence Risk Synthesizer"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        let anomaly_objectives: Vec<Box<dyn ExploitObjective>> = vec![
            Box::new(DifferentialConstraintObjective {
                rpc_url: self.rpc_url.clone(),
            }),
            Box::new(StateTransitionCycleObjective {
                rpc_url: self.rpc_url.clone(),
            }),
            Box::new(TaintFlowStorageCorruptionObjective {
                rpc_url: self.rpc_url.clone(),
            }),
        ];

        for anomaly in anomaly_objectives {
            let Some(seed) = anomaly.execute(bytecode) else {
                continue;
            };

            let Some(exploit) = enforce_composite_risk_with_market_solver(
                &self.rpc_url,
                self.chain_id,
                bytecode,
                &seed,
            ) else {
                continue;
            };

            let has_profit = exploit
                .expected_profit
                .map(|p| p > U256::ZERO)
                .unwrap_or(false);
            let has_corruption = !seed.steps.is_empty();
            if has_profit || has_corruption {
                return Some(exploit);
            }
        }

        None
    }
}

/// Strategy 14: Phantom Liquidity & Balance Deception (Balance Injection)
/// Injects bounded symbolic starting token balances into the target and checks
/// whether profitability appears only under injected-liquidity assumptions.
pub struct PhantomLiquidityObjective {
    pub rpc_url: String,
    pub chain_id: u64,
    pub max_injected_tokens: usize,
    pub max_injection_amount: U256,
}

impl ExploitObjective for PhantomLiquidityObjective {
    fn name(&self) -> &str {
        "Phantom Liquidity & Balance Deception"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "balance_injection_loan",
            )
            .ok()?;

            scenario.constrain_loan(solver, "1000000000000000000000000");
            let initial_token_vars = scenario.init_tokens(self.chain_id, bytecode);
            if initial_token_vars.is_empty() {
                return None;
            }

            let mut selectors = vec![
                Bytes::new(),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_TOKEN),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_ALL),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_UINT),
                Bytes::from_static(&crate::utils::selectors::CLAIM),
            ];
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();

            if selectors.is_empty() {
                return None;
            }

            // Keep this objective inside the 1800ms budget envelope.
            selectors.truncate(selectors.len().min(8));

            let max_injection_bv =
                crate::symbolic::z3_ext::bv_from_u256(ctx, self.max_injection_amount);
            let token_budget = self
                .max_injected_tokens
                .max(1)
                .min(initial_token_vars.len());

            for (idx, (token, _)) in initial_token_vars.iter().take(token_budget).enumerate() {
                let injection_snapshot = scenario.machine.snapshot();
                solver.push();

                let injected_balance = BV::new_const(ctx, format!("balance_inject_{}", idx), 256);
                let valid_injection =
                    constrained_positive_balance(ctx, &injected_balance, &max_injection_bv);
                solver.assert(&valid_injection);
                scenario
                    .machine
                    .token_balances
                    .insert((*token, scenario.contract_addr), injected_balance);

                let injected_result = solve_market_invariant(
                    ctx,
                    solver,
                    &mut scenario.machine,
                    scenario.db.clone(),
                    &scenario.flash_loan_amount,
                    &scenario.flash_loan_parts,
                    scenario.attacker,
                    scenario.contract_addr,
                    0,
                    3,
                    &selectors,
                    &initial_token_vars,
                );

                scenario.machine.restore(&injection_snapshot);
                solver.pop(1);

                if let Some(params) = injected_result {
                    // Differential guard: if the same selector is already exploitable with zero injection,
                    // this is not a balance-injection specific finding.
                    let pivot_selector = params
                        .steps
                        .last()
                        .map(|step| step.call_data.clone())
                        .unwrap_or_else(Bytes::new);
                    let baseline_selectors = vec![pivot_selector];

                    let baseline_snapshot = scenario.machine.snapshot();
                    solver.push();
                    let baseline_result = solve_market_invariant(
                        ctx,
                        solver,
                        &mut scenario.machine,
                        scenario.db.clone(),
                        &scenario.flash_loan_amount,
                        &scenario.flash_loan_parts,
                        scenario.attacker,
                        scenario.contract_addr,
                        0,
                        3,
                        &baseline_selectors,
                        &initial_token_vars,
                    );
                    scenario.machine.restore(&baseline_snapshot);
                    solver.pop(1);

                    if baseline_result.is_none() {
                        return Some(params);
                    }
                }
            }

            None
        })
    }
}

#[derive(Clone)]
struct UniV4HookTrace {
    success_execution: bool,
    reverted: bool,
    reentrancy_detected: bool,
    self_destructed: bool,
    storage_writes_len: usize,
    created_contracts_len: usize,
    hook_calls: Vec<HookCall>,
}

fn has_hook_reentrancy(trace: &UniV4HookTrace) -> bool {
    trace.reentrancy_detected && !trace.hook_calls.is_empty()
}

fn has_settlement_manipulation(trace: &UniV4HookTrace) -> bool {
    if trace.reverted || !trace.success_execution {
        return false;
    }
    trace
        .hook_calls
        .iter()
        .any(|hook| trace.storage_writes_len > hook.storage_log_len_at_call)
}

fn has_hook_high_value_effect(trace: &UniV4HookTrace) -> bool {
    trace.storage_writes_len > 0 || trace.created_contracts_len > 0 || trace.self_destructed
}

fn execute_uni_v4_hook_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> UniV4HookTrace {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.self_destructed = false;
    scenario.machine.reentrancy_detected = false;
    scenario.machine.storage_log.clear();
    scenario.machine.created_contracts.clear();
    scenario.machine.uniswap_v4_hook_calls.clear();

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

    let trace = UniV4HookTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        reentrancy_detected: scenario.machine.reentrancy_detected,
        self_destructed: scenario.machine.self_destructed,
        storage_writes_len: scenario.machine.storage_log.len(),
        created_contracts_len: scenario.machine.created_contracts.len(),
        hook_calls: scenario.machine.uniswap_v4_hook_calls.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

/// Strategy 9: Uniswap V4 Hook Manipulation
/// Detects hook-driven reentrancy and settlement-state mutation after hook callbacks.
pub struct UniV4HookManipulationObjective {
    pub rpc_url: String,
}

impl ExploitObjective for UniV4HookManipulationObjective {
    fn name(&self) -> &str {
        "Uniswap V4 Hook Manipulation"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "v4_hook_loan",
            )
            .ok()?;

            let mut selectors = vec![
                Bytes::new(),
                Bytes::from_static(&crate::utils::selectors::SWAP_EXACT_TOKENS_FOR_TOKENS),
                Bytes::from_static(&crate::utils::selectors::SWAP_EXACT_TOKENS_FOR_ETH),
                Bytes::from_static(&crate::utils::selectors::SWAP_EXACT_ETH_FOR_TOKENS),
            ];
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }

            // Keep solve budget under the 1800ms production gate.
            selectors.truncate(selectors.len().min(10));

            for call_data in &selectors {
                let trace = execute_uni_v4_hook_trace(solver, &mut scenario, call_data);
                if trace.hook_calls.is_empty() {
                    continue;
                }

                let hook_reentrancy = has_hook_reentrancy(&trace);
                let settlement_manipulation = has_settlement_manipulation(&trace);
                if (hook_reentrancy || settlement_manipulation)
                    && has_hook_high_value_effect(&trace)
                {
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
struct Erc4626Trace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes_len: usize,
    vault_states: HashMap<Address, Erc4626VaultState<'ctx>>,
}

fn execute_erc4626_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> Erc4626Trace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.storage_log.clear();
    scenario.machine.erc4626_vaults.clear();

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

    let trace = Erc4626Trace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes_len: scenario.machine.storage_log.len(),
        vault_states: scenario.machine.erc4626_vaults.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn erc4626_violation_sat<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    state: &Erc4626VaultState<'ctx>,
) -> bool {
    solver.push();
    let invariant = crate::protocols::erc4626::assets_per_share_non_decreasing(
        ctx,
        &state.initial_assets,
        &state.initial_supply,
        &state.current_assets,
        &state.current_supply,
    );
    solver.assert(&invariant.not());
    let sat = solver.check() == z3::SatResult::Sat;
    solver.pop(1);
    sat
}

/// Strategy 10: ERC-4626 Vault Shared Invariants
/// Flags cycles where totalAssets decreases relative to totalSupply.
pub struct Erc4626InvariantObjective {
    pub rpc_url: String,
}

impl ExploitObjective for Erc4626InvariantObjective {
    fn name(&self) -> &str {
        "ERC-4626 Vault Shared Invariants"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "erc4626_loan",
            )
            .ok()?;

            let mut selectors = vec![
                Bytes::new(),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW),
                Bytes::from_static(&crate::utils::selectors::REDEEM),
            ];
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }

            selectors.truncate(selectors.len().min(10));

            for call_data in &selectors {
                let trace = execute_erc4626_trace(solver, &mut scenario, call_data);
                if trace.reverted || !trace.success_execution || trace.vault_states.is_empty() {
                    continue;
                }

                let mut violated = false;
                for state in trace.vault_states.values() {
                    if !state.touched {
                        continue;
                    }
                    if erc4626_violation_sat(ctx, solver, state) {
                        violated = true;
                        break;
                    }
                }

                if violated && trace.storage_writes_len > 0 {
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

fn build_vault_inflation_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

/// Strategy 30: ERC-4626 Vault Inflation Risk (First Depositor)
/// Detects first-depositor donation inflation that forces victim deposits to round to zero shares.
pub struct VaultInflationObjective {
    pub rpc_url: String,
}

impl ExploitObjective for VaultInflationObjective {
    fn name(&self) -> &str {
        "ERC-4626 Vault Inflation Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::erc4626::has_vault_inflation_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "vault_inflation_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::erc4626::known_vault_inflation_selectors()
                    .iter()
                    .map(|selector| Bytes::copy_from_slice(&selector.to_be_bytes()))
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

            let total_supply = BV::new_const(ctx, "vault_inflation_total_supply", 256);
            let attacker_initial_deposit =
                BV::new_const(ctx, "vault_inflation_attacker_deposit", 256);
            let donation_amount = BV::new_const(ctx, "vault_inflation_donation_amount", 256);
            let victim_deposit = BV::new_const(ctx, "vault_inflation_victim_deposit", 256);
            let victim_shares_out = BV::new_const(ctx, "vault_inflation_victim_shares_out", 256);

            solver.assert(
                &crate::protocols::erc4626::first_depositor_inflation_drainable(
                    ctx,
                    &total_supply,
                    &attacker_initial_deposit,
                    &donation_amount,
                    &victim_deposit,
                    &victim_shares_out,
                ),
            );

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                flash_loan_legs: Vec::new(),
                steps: build_vault_inflation_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

fn build_share_rounding_griefing_steps(target: Address, selectors: &[Bytes]) -> Vec<ExploitStep> {
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

/// Strategy 31: ERC-4626 Share Rounding Griefing
/// Detects profitable deposit->withdraw roundtrip leakage where attacker assets increase.
pub struct ShareRoundingGriefingObjective {
    pub rpc_url: String,
}
