impl ExploitObjective for ShareRoundingGriefingObjective {
    fn name(&self) -> &str {
        "ERC-4626 Share Rounding Griefing"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::erc4626::has_share_rounding_griefing_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "share_rounding_griefing_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> = crate::protocols::erc4626::all_selectors()
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

            let attacker_assets_pre_roundtrip =
                BV::new_const(ctx, "erc4626_attacker_assets_pre_roundtrip", 256);
            let attacker_assets_post_roundtrip =
                BV::new_const(ctx, "erc4626_attacker_assets_post_roundtrip", 256);

            solver.assert(&crate::protocols::erc4626::share_roundtrip_leaks_assets(
                ctx,
                &attacker_assets_pre_roundtrip,
                &attacker_assets_post_roundtrip,
            ));

            if solver.check() != z3::SatResult::Sat {
                return None;
            }

            Some(ExploitParams {
                flash_loan_amount: U256::ZERO,
                flash_loan_token: Address::ZERO,
                flash_loan_provider: Address::ZERO,
                               flash_loan_legs: Vec::new(),
                steps: build_share_rounding_griefing_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

// SHARED PROFIT CHECKER
pub fn is_profitable<'ctx>(
    ctx: &'ctx Context,
    machine: &SymbolicMachine<'ctx>,
    attacker: Address,
    total_cost: &BV<'ctx>,
    flash_loan_amount: &BV<'ctx>, // Explicit Liability
    initial_token_vars: &[(Address, BV<'ctx>)],
) -> Bool<'ctx> {
    // 1. Economic Invariant: Solvency (Must repay Flash Loan)
    // protocol_assets >= protocol_liabilities implies final_eth >= loan_amount
    let eth_solvent = if let Some(final_balance) = machine.balance_overrides.get(&attacker) {
        final_balance.bvuge(flash_loan_amount)
    } else {
        // If we can't prove ETH balance, we assume insolvency (Conservative)
        Bool::from_bool(ctx, false)
    };

    // 2. Condition A: Native ETH Profit (Net Positive after repaying loan & gas)
    let eth_profit = if let Some(final_balance) = machine.balance_overrides.get(&attacker) {
        let margin = val(ctx, PROFIT_MARGIN);
        let cost_with_margin = total_cost.bvadd(&margin);

        let min_required = cost_with_margin.bvadd(flash_loan_amount);

        // CHECK OVERFLOW: min_required must be >= flash_loan_amount
        let no_overflow = min_required.bvuge(flash_loan_amount);

        let is_profitable = final_balance.bvugt(&min_required);
        Bool::and(ctx, &[&is_profitable, &no_overflow])
    } else {
        Bool::from_bool(ctx, false)
    };

    // 3. Condition B: Token Profit (Any increase in token balance)
    let mut token_profit = Bool::from_bool(ctx, false);
    for (token, initial_bal) in initial_token_vars {
        if let Some(final_bal) = machine.token_balances.get(&(*token, attacker)) {
            let is_gt = final_bal.bvugt(initial_bal);
            token_profit = Bool::or(ctx, &[&token_profit, &is_gt]);
        }
    }

    // 4. Final Logic: (Solvent AND (ETH_Profit OR Token_Profit))
    // Note: ETH_Profit implies Solvency, but Token_Profit does NOT.
    // This AND enforces that even if we gain tokens, we MUST be solvent in ETH.
    let any_profit = Bool::or(ctx, &[&eth_profit, &token_profit]);
    Bool::and(ctx, &[&eth_solvent, &any_profit])
}

fn passes_solve_phase_slippage_guard<'ctx>(
    machine: &SymbolicMachine<'ctx>,
    chain_id: u64,
    params: &ExploitParams,
) -> bool {
    if !crate::solver::liquidity::slippage_solver_constraint_enabled() {
        return true;
    }

    let Some(rpc_url) = machine.fork_url.as_deref() else {
        tracing::debug!(
            "[SLIPPAGE] Solve-phase gate enabled but no fork RPC URL on symbolic machine; skipping gate."
        );
        return true;
    };

    match crate::solver::liquidity::verify_exact_input_single_liquidity_blocking(
        chain_id, rpc_url, params,
    ) {
        Ok(Some(result)) => {
            if !result.passed {
                tracing::debug!(
                    "[SLIPPAGE] Solve-phase reject: quoted_out={} < amountOutMinimum={}",
                    result.quoted_out,
                    result.required_min_out
                );
            }
            result.passed
        }
        Ok(None) => true,
        Err(err) => {
            tracing::warn!("[SLIPPAGE] Solve-phase oracle error: {}", err);
            !crate::solver::liquidity::slippage_oracle_strict()
        }
    }
}

fn choose_primary_flash_loan_source(
    legs: &[crate::solver::objectives::FlashLoanLeg],
    fallback_token: Address,
) -> Option<(Address, Address)> {
    legs.iter()
        .filter(|leg| !leg.amount.is_zero())
        .min_by(|a, b| {
            a.fee_bps
                .cmp(&b.fee_bps)
                .then_with(|| a.provider.as_slice().cmp(b.provider.as_slice()))
        })
        .map(|leg| {
            let token = if leg.token == Address::ZERO {
                fallback_token
            } else {
                leg.token
            };
            (leg.provider, token)
        })
}

// SHARED SOLVER LOGIC
// Extracted from GenericProfitObjective to allow reuse by GuidedProfitObjective
#[allow(clippy::too_many_arguments)]
pub fn solve_market_invariant<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    machine: &mut SymbolicMachine<'ctx>,
    db: CacheDB<ForkDB>,
    flash_loan_amount: &BV<'ctx>,
    flash_loan_parts: &[crate::solver::setup::FlashLoanPart<'ctx>],
    attacker: Address,
    contract_addr: Address,
    depth: usize,
    max_depth: usize,
    selectors: &[Bytes],
    initial_token_vars: &[(Address, BV<'ctx>)],
) -> Option<ExploitParams> {
    if depth >= max_depth {
        return None;
    }

    for call_data in selectors {
        if crate::solver::soundness::is_selector_blocked(contract_addr, call_data) {
            tracing::debug!(
                "[SOUNDNESS] Skipping blocked selector for {:?}: 0x{}",
                contract_addr,
                hex::encode(&call_data[..4.min(call_data.len())])
            );
            continue;
        }
        if crate::solver::honeypot::is_honeypot_selector(contract_addr, call_data) {
            tracing::debug!(
                "[HONEYPOT] Skipping selector flagged as admin-key honeypot for {:?}: 0x{}",
                contract_addr,
                hex::encode(&call_data[..4.min(call_data.len())])
            );
            continue;
        }
        if crate::solver::gas_grief::is_gas_grief_selector(contract_addr, call_data) {
            tracing::debug!(
                "[GAS_GRIEF] Skipping selector flagged as gas grief trap for {:?}: 0x{}",
                contract_addr,
                hex::encode(&call_data[..4.min(call_data.len())])
            );
            continue;
        }

        // ITERATION 6: Snapshot State (Isolation handled in state.rs)
        let mut current_db = db.clone();
        let mut invariant_db = db.clone();
        let mut invariant_checker = GlobalInvariantChecker::default();

        solver.push(); // Single scope per selector iteration (popped at end or on early return)
        let snapshot = machine.snapshot();

        // Define Costs before exploration
        let gas_cost_eth = U256::from(200_000 * 10_000_000_000u64 * (depth as u64 + 1));
        let gas_bv = crate::symbolic::z3_ext::bv_from_u256(machine.context, gas_cost_eth);
        let loan_fee = zero(ctx);
        let total_cost = loan_fee.bvadd(&gas_bv);

        fn load_u64_env(name: &str) -> Option<u64> {
            std::env::var(name)
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
        }

        fn symbolic_chain_id() -> Option<u64> {
            match load_u64_env("CHAIN_ID") {
                Some(chain_id) => Some(chain_id),
                None if cfg!(test) => Some(8453),
                None => None,
            }
        }

        fn symbolic_block_number() -> u64 {
            // Use a non-zero, mainnet-ish value so `block.number` guards don't trivially short-circuit.
            load_u64_env("SYMBOLIC_BLOCK_NUMBER").unwrap_or(10_000_000)
        }

        fn symbolic_block_timestamp() -> u64 {
            // Roughly mid-2023+ epoch; avoids `timestamp==0` shortcut branches in fee/timelock logic.
            load_u64_env("SYMBOLIC_BLOCK_TIMESTAMP").unwrap_or(1_700_000_000)
        }

        fn symbolic_basefee_wei() -> u64 {
            // Default 1 gwei basefee; conservative non-zero to avoid "free gas" false positives.
            load_u64_env("SYMBOLIC_BASEFEE_WEI").unwrap_or(1_000_000_000)
        }

        fn symbolic_gasprice_wei() -> u64 {
            // Default gasprice ~= basefee; override for chain-specific tuning when needed.
            load_u64_env("SYMBOLIC_GASPRICE_WEI").unwrap_or_else(symbolic_basefee_wei)
        }

        let Some(symbolic_chain_id) = symbolic_chain_id() else {
            tracing::warn!(
                "[WARN] Missing CHAIN_ID for symbolic execution modeling; skipping objective solve."
            );
            solver.pop(1);
            machine.restore(&snapshot);
            continue;
        };

        // Multi-path exploration loop
        loop {
            let start_pushes = machine.branch_pushes;
            // Isolated Calldata
            machine.reset_calldata();
            machine.tx_id += 1;

            let result;
            let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut evm = Evm::builder()
                    .with_db(&mut current_db)
                    .with_external_context(&mut *machine)
                    .append_handler_register(revm::inspector_handle_register)
                    .modify_tx_env(|tx| {
                        tx.caller = attacker;
                        tx.transact_to = TransactTo::Call(contract_addr);
                        tx.data = call_data.clone();
                        tx.value = U256::ZERO;
                        tx.gas_limit = 10_000_000;
                    })
                    .build();
                // L2 opcode soundness: avoid default-zero block/fee env that can cause symbolic/replay drift.
                evm.context.evm.env.cfg.chain_id = symbolic_chain_id;
                evm.context.evm.env.block.number = U256::from(symbolic_block_number());
                evm.context.evm.env.block.timestamp = U256::from(symbolic_block_timestamp());
                evm.context.evm.env.block.basefee = U256::from(symbolic_basefee_wei());
                evm.context.evm.env.tx.gas_price = U256::from(symbolic_gasprice_wei());
                evm.transact_commit()
            }));
            result = match guarded {
                Ok(exec_result) => exec_result,
                Err(payload) => {
                    let reason = panic_payload_to_string(payload.as_ref());
                    eprintln!(
                            "[WARN] Panic Propagation Guard: symbolic loop panicked at depth {} with selector {:?}: {}",
                            depth, call_data, reason
                        );
                    machine.reverted = true;
                    break;
                }
            };

            // Check for implicit EVM failures (OOM, Stack, etc) that don't trigger REVERT opcode
            // but do fail the transaction.
            // UNWRAP SAFETY: result is Result<ExecutionResult, EVMError>
            // We treat any Err or non-Success as a revert.
            let success_execution = if let Ok(res) = result {
                matches!(res, revm::primitives::ExecutionResult::Success { .. })
            } else {
                false
            };

            // Check if we found a profit in THIS path
            let found_profit = if machine.reverted || !success_execution {
                false
            } else {
                solver.push();
                let profitable = is_profitable(
                    ctx,
                    machine,
                    attacker,
                    &total_cost,
                    flash_loan_amount,
                    initial_token_vars,
                );
                solver.assert(&profitable);
                let triple_gate = invariant_checker.build_constraints(
                    ctx,
                    machine,
                    &mut invariant_db,
                    attacker,
                    flash_loan_amount,
                );
                solver.assert(&triple_gate);
                let res = solver.check();
                solver.pop(1);
                res == z3::SatResult::Sat
            };

            if found_profit {
                break; // We found it!
            }

            // If not, check if we have unexplored branches to try
            if let Some((pc, decision)) = machine.unexplored_branches.pop() {
                // Backtrack Z3 to pre-tx state AND restore machine state
                // Backtrack Z3 to pre-tx state AND restore machine state
                machine.restore(&snapshot);

                // Restore the concrete DB to the snapshot so symbolic and concrete state stay aligned.
                // The concrete execution must match the symbolic state.
                current_db = db.clone();

                // Insert the forced path constraint after `restore()`,
                // because restore() overwrites path_constraints with the snapshot's copy.
                machine.path_constraints.insert(pc, decision);

                machine.branch_pushes = start_pushes;

                // We loop and run again with the new constraint
                continue;
            }

            break; // No more paths for this selector
        }

        // Prevent post-loop processing on a branch that never produced a terminal result.
        if !machine.reverted {
            // A. Check for profit with unified logic
            solver.push();
            let profitable = is_profitable(
                ctx,
                machine,
                attacker,
                &total_cost,
                flash_loan_amount,
                initial_token_vars,
            );
            solver.assert(&profitable);
            let triple_gate = invariant_checker.build_constraints(
                ctx,
                machine,
                &mut invariant_db,
                attacker,
                flash_loan_amount,
            );
            solver.assert(&triple_gate);

            // Repayment-based paths can be valid even when final balance is not strictly above the loan.
            // This gate verifies net profitability (profit above gas cost) instead.

            let res = solver.check();
            if res == z3::SatResult::Sat {
                if let Some(model) = solver.get_model() {
                    let loan_sol = model.eval::<BV>(flash_loan_amount, true);
                    let profit_eval = model
                        .eval::<BV>(&total_cost, true)
                        .and_then(|v| u256_from_bv(&v));

                    if let Some(loan_val) = loan_sol {
                        if let Some(loan_u256) = u256_from_bv(&loan_val) {
                            let mut legs = Vec::new();
                            for part in flash_loan_parts {
                                if let Some(part_bv) = model.eval::<BV>(&part.amount, true) {
                                    if let Some(part_u256) = u256_from_bv(&part_bv) {
                                        if !part_u256.is_zero() {
                                            legs.push(crate::solver::objectives::FlashLoanLeg {
                                                provider: part.provider,
                                                token: part.token,
                                                amount: part_u256,
                                                fee_bps: part.fee_bps,
                                            });
                                        }
                                    }
                                }
                            }
                            let chain_weth =
                                crate::config::chains::ChainConfig::get(symbolic_chain_id).weth;
                            let (flash_loan_provider, flash_loan_token) =
                                choose_primary_flash_loan_source(&legs, chain_weth)
                                    .unwrap_or((Address::ZERO, Address::ZERO));
                            let candidate = ExploitParams {
                                flash_loan_amount: loan_u256,
                                flash_loan_token,
                                flash_loan_provider,
                                                               flash_loan_legs: legs,
                                steps: vec![ExploitStep {
                                    target: contract_addr,
                                    call_data: call_data.clone(),
                                    execute_if: None,
                                }],
                                expected_profit: profit_eval,
                                block_offsets: None,
                            };
                            if !passes_solve_phase_slippage_guard(
                                machine,
                                symbolic_chain_id,
                                &candidate,
                            ) {
                                solver.pop(1); // Pop profit-check scope
                                machine.restore(&snapshot);
                                solver.pop(1); // Pop selector scope
                                continue;
                            }
                            solver.pop(1); // Pop profit-check scope
                            machine.restore(&snapshot);
                            solver.pop(1); // Pop selector scope
                            return Some(candidate);
                        }
                    }
                }
            }
            solver.pop(1);

            // B. Check Stack Result
            if !machine.sym_stack.is_empty() {
                let output_bv = machine.sym_stack.peek(0);
                solver.push();
                let is_gt = output_bv.bvugt(&total_cost);
                solver.assert(&is_gt);
                let triple_gate = invariant_checker.build_constraints(
                    ctx,
                    machine,
                    &mut invariant_db,
                    attacker,
                    flash_loan_amount,
                );
                solver.assert(&triple_gate);
                let res = solver.check();
                if res == z3::SatResult::Sat {
                    if let Some(model) = solver.get_model() {
                        if let Some(loan_sol) = model.eval::<BV>(flash_loan_amount, true) {
                            if let Some(loan_u256) = u256_from_bv(&loan_sol) {
                                let profit_eval = model
                                    .eval::<BV>(&total_cost, true)
                                    .and_then(|v| u256_from_bv(&v));

                                let mut legs = Vec::new();
                                for part in flash_loan_parts {
                                    if let Some(part_bv) = model.eval::<BV>(&part.amount, true) {
                                        if let Some(part_u256) = u256_from_bv(&part_bv) {
                                            if !part_u256.is_zero() {
                                                legs.push(crate::solver::objectives::FlashLoanLeg {
                                                    provider: part.provider,
                                                    token: part.token,
                                                    amount: part_u256,
                                                    fee_bps: part.fee_bps,
                                                });
                                            }
                                        }
                                    }
                                }
                                let chain_weth =
                                    crate::config::chains::ChainConfig::get(symbolic_chain_id).weth;
                                let (flash_loan_provider, flash_loan_token) =
                                    choose_primary_flash_loan_source(&legs, chain_weth)
                                        .unwrap_or((Address::ZERO, Address::ZERO));
                                let candidate = ExploitParams {
                                    flash_loan_amount: loan_u256,
                                    flash_loan_provider,
                                    flash_loan_token,
                                    flash_loan_legs: legs,
                                    steps: vec![ExploitStep {
                                        target: contract_addr,
                                        call_data: call_data.clone(),
                                        execute_if: None,
                                    }],
                                    expected_profit: profit_eval,
                                    block_offsets: None,
                                };
                                if !passes_solve_phase_slippage_guard(
                                    machine,
                                    symbolic_chain_id,
                                    &candidate,
                                ) {
                                    solver.pop(1); // Pop stack-check scope
                                    machine.restore(&snapshot);
                                    solver.pop(1); // Pop selector scope
                                    continue;
                                }
                                solver.pop(1); // Pop stack-check scope
                                machine.restore(&snapshot);
                                solver.pop(1); // Pop selector scope
                                return Some(candidate);
                            }
                        }
                    }
                }
                solver.pop(1);
            }

            // D. Recurse
            if depth < max_depth {
                if let Some(mut params) = solve_market_invariant(
                    ctx,
                    solver,
                    machine,
                    current_db,
                    flash_loan_amount,
                    flash_loan_parts,
                    attacker,
                    contract_addr,
                    depth + 1,
                    max_depth,
                    selectors,
                    initial_token_vars,
                ) {
                    params.steps.insert(
                        0,
                        ExploitStep {
                            target: contract_addr,
                            call_data: call_data.clone(),
                            execute_if: None,
                        },
                    );
                    if !passes_solve_phase_slippage_guard(machine, symbolic_chain_id, &params) {
                        machine.restore(&snapshot);
                        solver.pop(1); // Pop selector scope before continue
                        continue;
                    }
                    machine.restore(&snapshot);
                    solver.pop(1); // Pop selector scope before return
                    return Some(params);
                }
            }
        }

        machine.restore(&snapshot);
        solver.pop(1); // Pop selector scope (normal path)
    }
    None
}

// Placeholder Objective for future expansion
pub struct PlaceholderObjective {
    pub rpc_url: String,
    pub label: &'static str,
}

impl ExploitObjective for PlaceholderObjective {
    fn name(&self) -> &str {
        self.label
    }

    fn execute(&self, _bytecode: &Bytes) -> Option<ExploitParams> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_ratio_gap_exceeds_bps_sat_on_large_gap() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let uni_num = BV::from_u64(&ctx, 70, 256);
        let uni_den = BV::from_u64(&ctx, 100, 256);
        let curve_num = BV::from_u64(&ctx, 100, 256);
        let curve_den = BV::from_u64(&ctx, 100, 256);

        let gap = ratio_gap_exceeds_bps(&ctx, &uni_num, &uni_den, &curve_num, &curve_den, 250);
        solver.assert(&gap);
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_ratio_gap_exceeds_bps_unsat_on_tight_prices() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let uni_num = BV::from_u64(&ctx, 101, 256);
        let uni_den = BV::from_u64(&ctx, 100, 256);
        let curve_num = BV::from_u64(&ctx, 100, 256);
        let curve_den = BV::from_u64(&ctx, 100, 256);

        let gap = ratio_gap_exceeds_bps(&ctx, &uni_num, &uni_den, &curve_num, &curve_den, 250);
        solver.assert(&gap);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_ratio_gap_within_bps_sat_on_anchor_window() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let curve_num = BV::from_u64(&ctx, 1005, 256);
        let curve_den = BV::from_u64(&ctx, 1000, 256);
        let uni_num = BV::from_u64(&ctx, 1000, 256);
        let uni_den = BV::from_u64(&ctx, 1000, 256);

        let anchored = ratio_gap_within_bps(&ctx, &curve_num, &curve_den, &uni_num, &uni_den, 80);
        solver.assert(&anchored);
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_collect_oracle_sources_dedup_and_filter() {
        let pair = Address::from([0x11; 20]);
        let chainlink = Address::from([0x22; 20]);
        let vault = Address::from([0x33; 20]);
        let deps = vec![
            OracleDep {
                source: pair,
                target: pair,
                slot: U256::ZERO,
                kind: OracleType::UniV2Reserves,
            },
            OracleDep {
                source: pair,
                target: pair,
                slot: U256::ZERO,
                kind: OracleType::UniV2Reserves,
            },
            OracleDep {
                source: chainlink,
                target: chainlink,
                slot: U256::ZERO,
                kind: OracleType::ChainlinkFeed,
            },
            OracleDep {
                source: vault,
                target: vault,
                slot: U256::ZERO,
                kind: OracleType::ERC4626TotalAssets,
            },
        ];

        let (pairs, feeds) = collect_oracle_sources(&deps);
        assert_eq!(pairs, vec![pair]);
        assert_eq!(feeds, vec![chainlink]);
    }

    #[test]
    fn test_panic_payload_to_string_handles_str_and_string() {
        let as_str = "panic-str";
        assert_eq!(panic_payload_to_string(&as_str), "panic-str".to_string());

        let as_string = "panic-string".to_string();
        assert_eq!(
            panic_payload_to_string(&as_string),
            "panic-string".to_string()
        );
    }

    #[test]
    fn test_sender_lift_equivalence_accepts_identical_high_value_delta() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let shared_key = BV::from_u64(&ctx, 7, 256);
        let shared_val = BV::from_u64(&ctx, 11, 256);
        let mut pcs = HashMap::new();
        pcs.insert(10usize, 1usize);
        pcs.insert(11usize, 1usize);

        let privileged = SenderLiftTrace {
            success_execution: true,
            reverted: false,
            self_destructed: false,
            visited_pcs: pcs.clone(),
            storage_writes: vec![(shared_key.clone(), shared_val.clone())],
            created_contracts_len: 0,
        };
        let outsider = SenderLiftTrace {
            success_execution: true,
            reverted: false,
            self_destructed: false,
            visited_pcs: pcs,
            storage_writes: vec![(shared_key, shared_val)],
            created_contracts_len: 0,
        };

        assert!(sender_lift_equivalent(&privileged, &outsider));
        assert!(has_high_value_state_change(&privileged));
    }

    #[test]
    fn test_sender_lift_equivalence_rejects_sender_dependent_write() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let key = BV::from_u64(&ctx, 9, 256);
        let mut pcs = HashMap::new();
        pcs.insert(22usize, 1usize);

        let privileged = SenderLiftTrace {
            success_execution: true,
            reverted: false,
            self_destructed: false,
            visited_pcs: pcs.clone(),
            storage_writes: vec![(key.clone(), BV::from_u64(&ctx, 1, 256))],
            created_contracts_len: 0,
        };
        let outsider = SenderLiftTrace {
            success_execution: true,
            reverted: false,
            self_destructed: false,
            visited_pcs: pcs,
            storage_writes: vec![(key, BV::from_u64(&ctx, 2, 256))],
            created_contracts_len: 0,
        };

        assert!(!sender_lift_equivalent(&privileged, &outsider));
    }

    #[test]
    fn test_low_slot_owner_takeover_detects_attacker_assignment() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);
        let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
            &ctx,
            U256::from_be_bytes(attacker.into_word().into()),
        );

        let writes = vec![(
            BV::from_u64(&ctx, 0, 256),
            crate::symbolic::z3_ext::bv_from_u256(
                &ctx,
                U256::from_be_bytes(attacker.into_word().into()),
            ),
        )];

        assert!(has_low_slot_owner_takeover(
            &ctx,
            &solver,
            &writes,
            &attacker_word
        ));
    }

    #[test]
    fn test_low_slot_owner_takeover_rejects_non_low_slot_assignment() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);
        let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
            &ctx,
            U256::from_be_bytes(attacker.into_word().into()),
        );

        let writes = vec![(
            BV::from_u64(&ctx, 8, 256),
            crate::symbolic::z3_ext::bv_from_u256(
                &ctx,
                U256::from_be_bytes(attacker.into_word().into()),
            ),
        )];

        assert!(!has_low_slot_owner_takeover(
            &ctx,
            &solver,
            &writes,
            &attacker_word
        ));
    }

    #[test]
    fn test_fee_on_transfer_mismatch_detects_inbound_shortfall_with_state_mutation() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let contract = Address::from([0x44; 20]);

        let trace = FeeOnTransferTrace {
            success_execution: true,
            reverted: false,
            storage_writes_len: 1,
            transfer_events: vec![TokenTransferEvent {
                token: Address::from([0x55; 20]),
                from: Address::from([0x11; 20]),
                to: contract,
                requested_amount: BV::from_u64(&ctx, 100, 256),
                received_amount: BV::from_u64(&ctx, 95, 256),
                via_transfer_from: true,
            }],
        };

        assert!(has_fee_on_transfer_accounting_mismatch(
            &ctx, &solver, contract, &trace
        ));
    }

    #[test]
    fn test_fee_on_transfer_mismatch_rejects_equal_received_amount() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let contract = Address::from([0x44; 20]);

        let trace = FeeOnTransferTrace {
            success_execution: true,
            reverted: false,
            storage_writes_len: 2,
            transfer_events: vec![TokenTransferEvent {
                token: Address::from([0x55; 20]),
                from: Address::from([0x11; 20]),
                to: contract,
                requested_amount: BV::from_u64(&ctx, 100, 256),
                received_amount: BV::from_u64(&ctx, 100, 256),
                via_transfer_from: true,
            }],
        };

        assert!(!has_fee_on_transfer_accounting_mismatch(
            &ctx, &solver, contract, &trace
        ));
    }

    #[test]
    fn test_psm_drain_signal_detects_cross_token_spread() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);
        let contract = Address::from([0x44; 20]);

        let trace = PsmTrace {
            success_execution: true,
            reverted: false,
            storage_writes_len: 1,
            transfer_events: vec![
                TokenTransferEvent {
                    token: Address::from([0x11; 20]),
                    from: attacker,
                    to: contract,
                    requested_amount: BV::from_u64(&ctx, 100, 256),
                    received_amount: BV::from_u64(&ctx, 100, 256),
                    via_transfer_from: true,
                },
                TokenTransferEvent {
                    token: Address::from([0x22; 20]),
                    from: contract,
                    to: attacker,
                    requested_amount: BV::from_u64(&ctx, 110, 256),
                    received_amount: BV::from_u64(&ctx, 110, 256),
                    via_transfer_from: false,
                },
            ],
        };

        assert!(has_psm_drain_signal(
            &ctx, &solver, attacker, contract, 500, &trace
        ));
    }

    #[test]
    fn test_psm_drain_signal_rejects_same_token_roundtrip() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);
        let contract = Address::from([0x44; 20]);
        let token = Address::from([0x11; 20]);

        let trace = PsmTrace {
            success_execution: true,
            reverted: false,
            storage_writes_len: 1,
            transfer_events: vec![
                TokenTransferEvent {
                    token,
                    from: attacker,
                    to: contract,
                    requested_amount: BV::from_u64(&ctx, 100, 256),
                    received_amount: BV::from_u64(&ctx, 100, 256),
                    via_transfer_from: true,
                },
                TokenTransferEvent {
                    token,
                    from: contract,
                    to: attacker,
                    requested_amount: BV::from_u64(&ctx, 110, 256),
                    received_amount: BV::from_u64(&ctx, 110, 256),
                    via_transfer_from: false,
                },
            ],
        };

        assert!(!has_psm_drain_signal(
            &ctx, &solver, attacker, contract, 500, &trace
        ));
    }

    #[test]
    fn test_reserve_drop_exceeds_bps_accepts_large_drop() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let pre = BV::from_u64(&ctx, 1000, 256);
        let post = BV::from_u64(&ctx, 800, 256);

        solver.assert(&reserve_drop_exceeds_bps(&ctx, &pre, &post, 500));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_liquidation_spiral_drop_detects_slot_decrease() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let trace = LiquidationSpiralTrace {
            success_execution: true,
            reverted: false,
            slot_deltas: vec![LiquidationSpiralSlotDelta {
                pre_value: BV::from_u64(&ctx, 1000, 256),
                post_value: BV::from_u64(&ctx, 900, 256),
            }],
        };

        assert!(has_liquidation_spiral_drop(&ctx, &solver, 500, &trace));
    }

    #[test]
    fn test_build_block_offsets_requires_multiple_steps() {
        assert!(build_block_offsets(1).is_none());
        assert_eq!(build_block_offsets(2), Some(vec![0, 1]));
    }

    #[test]
    fn test_build_interest_rate_gaming_steps_caps_to_three() {
        let target = Address::from([0x44; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_interest_rate_gaming_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_collateral_factor_lag_violation_detects_stale_oracle_window() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let collateral = BV::from_u64(&ctx, 10_000, 256);
        let debt = BV::from_u64(&ctx, 8_900, 256);

        solver.assert(&collateral_factor_lag_violation(
            &ctx,
            &collateral,
            &debt,
            9_000,
            8_700,
            5_000,
        ));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_collateral_factor_lag_violation_rejects_low_initial_ltv() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let collateral = BV::from_u64(&ctx, 10_000, 256);
        let debt = BV::from_u64(&ctx, 6_500, 256);

        solver.assert(&collateral_factor_lag_violation(
            &ctx,
            &collateral,
            &debt,
            9_000,
            8_700,
            5_000,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_build_collateral_factor_ltv_lag_steps_caps_to_three() {
        let target = Address::from([0x55; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_collateral_factor_ltv_lag_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_redemption_arbitrage_steps_caps_to_three() {
        let target = Address::from([0x66; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_redemption_arbitrage_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_dust_bad_debt_steps_caps_to_three() {
        let target = Address::from([0x77; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_dust_bad_debt_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_amm_price_impact_steps_caps_to_three() {
        let target = Address::from([0x88; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_amm_price_impact_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_weak_prng_steps_caps_to_three() {
        let target = Address::from([0x99; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_weak_prng_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_commit_reveal_bypass_steps_caps_to_three() {
        let target = Address::from([0xa9; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_commit_reveal_bypass_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_gambling_contract_scanner_steps_caps_to_three() {
        let target = Address::from([0xb9; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_gambling_contract_scanner_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_chainlink_vrf_timing_steps_caps_to_three() {
        let target = Address::from([0xc9; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_chainlink_vrf_timing_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_governance_flash_vote_steps_caps_to_three() {
        let target = Address::from([0xd9; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_governance_flash_vote_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_timelock_expiry_sniping_steps_caps_to_three() {
        let target = Address::from([0xe9; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_timelock_expiry_sniping_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_quorum_manipulation_steps_caps_to_three() {
        let target = Address::from([0xf9; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_quorum_manipulation_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_delegatee_hijack_steps_caps_to_three() {
        let target = Address::from([0xa7; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_delegatee_hijack_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_erc721_callback_reentrancy_steps_caps_to_three() {
        let target = Address::from([0xb7; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_erc721_callback_reentrancy_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_erc1155_callback_reentrancy_steps_caps_to_three() {
        let target = Address::from([0xc7; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_erc1155_callback_reentrancy_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_erc721_mint_callback_drain_steps_caps_to_three() {
        let target = Address::from([0xd7; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_erc721_mint_callback_drain_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_erc721_approval_hijack_steps_caps_to_three() {
        let target = Address::from([0xe7; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_erc721_approval_hijack_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_read_only_reentrancy_steps_caps_to_three() {
        let target = Address::from([0xf7; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_read_only_reentrancy_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_read_only_reentrancy_scanner_steps_caps_to_three() {
        let target = Address::from([0x17; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_read_only_reentrancy_scanner_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_vault_inflation_steps_caps_to_three() {
        let target = Address::from([0x27; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_vault_inflation_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_build_share_rounding_griefing_steps_caps_to_three() {
        let target = Address::from([0x37; 20]);
        let selectors = vec![
            Bytes::from_static(&[0x11, 0x11, 0x11, 0x11]),
            Bytes::from_static(&[0x22, 0x22, 0x22, 0x22]),
            Bytes::from_static(&[0x33, 0x33, 0x33, 0x33]),
            Bytes::from_static(&[0x44, 0x44, 0x44, 0x44]),
        ];

        let steps = build_share_rounding_griefing_steps(target, &selectors);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].target, target);
        assert_eq!(steps[0].call_data, selectors[0]);
    }

    #[test]
    fn test_symbolic_fuzz_anomaly_detects_storage_write_burst() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);

        let trace = SymbolicFuzzTrace {
            success_execution: true,
            reverted: false,
            storage_writes_len: SYMBOLIC_FUZZ_STORAGE_WRITE_THRESHOLD + 1,
            transfer_events: vec![],
        };

        assert!(has_symbolic_fuzz_anomaly(&ctx, &solver, attacker, &trace));
    }

    #[test]
    fn test_symbolic_fuzz_anomaly_detects_large_attacker_transfer() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);
        let transfer_amount =
            crate::symbolic::z3_ext::bv_from_u256(&ctx, symbolic_fuzz_token_print_threshold());

        let trace = SymbolicFuzzTrace {
            success_execution: true,
            reverted: false,
            storage_writes_len: 0,
            transfer_events: vec![TokenTransferEvent {
                token: Address::from([0x55; 20]),
                from: Address::from([0x11; 20]),
                to: attacker,
                requested_amount: transfer_amount.clone(),
                received_amount: transfer_amount.bvadd(&BV::from_u64(&ctx, 1, 256)),
                via_transfer_from: false,
            }],
        };

        assert!(has_symbolic_fuzz_anomaly(&ctx, &solver, attacker, &trace));
    }

    #[test]
    fn test_symbolic_fuzz_anomaly_rejects_reverted_trace() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker = Address::from([0xAA; 20]);

        let trace = SymbolicFuzzTrace {
            success_execution: true,
            reverted: true,
            storage_writes_len: SYMBOLIC_FUZZ_STORAGE_WRITE_THRESHOLD + 8,
            transfer_events: vec![],
        };

        assert!(!has_symbolic_fuzz_anomaly(&ctx, &solver, attacker, &trace));
    }

    #[test]
    fn test_differential_constraint_gap_detects_strict_weakening() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let amount = BV::new_const(&ctx, "logic_gap_amount", 256);
        let zero = BV::from_u64(&ctx, 0, 256);
        let one = BV::from_u64(&ctx, 1, 256);

        let strict_positive = amount.bvugt(&one);
        let non_zero = amount._eq(&zero).not();

        assert!(has_differential_constraint_gap(
            &solver,
            &strict_positive,
            &non_zero
        ));
    }

    #[test]
    fn test_differential_constraint_gap_rejects_equivalent_constraints() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let amount = BV::new_const(&ctx, "logic_gap_amount_eq", 256);
        let zero = BV::from_u64(&ctx, 0, 256);

        let non_zero = amount._eq(&zero).not();

        assert!(!has_differential_constraint_gap(
            &solver, &non_zero, &non_zero
        ));
    }

    #[test]
    fn test_same_slot_possible_detects_alias() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let key = BV::new_const(&ctx, "shared_slot", 256);

        assert!(same_slot_possible(&solver, &key, &key));
    }

    #[test]
    fn test_tarjan_scc_detects_privileged_cycle_component() {
        let components = tarjan_scc(
            2,
            &[
                (STG_UNPRIVILEGED, STG_PRIVILEGED),
                (STG_PRIVILEGED, STG_UNPRIVILEGED),
            ],
        );

        assert!(components.iter().any(|component| {
            component.contains(&STG_UNPRIVILEGED) && component.contains(&STG_PRIVILEGED)
        }));
    }

    #[test]
    fn test_tarjan_scc_splits_acyclic_transitions() {
        let components = tarjan_scc(2, &[(STG_UNPRIVILEGED, STG_PRIVILEGED)]);

        assert!(components
            .iter()
            .all(|component| !(component.contains(&STG_UNPRIVILEGED)
                && component.contains(&STG_PRIVILEGED))));
    }

    #[test]
    fn test_key_depends_on_user_input_detects_calldata_symbol() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let symbolic_key = BV::new_const(&ctx, "calldata_root_alias_key", 256);
        let concrete_key = BV::from_u64(&ctx, 7, 256);

        assert!(key_depends_on_user_input(&symbolic_key));
        assert!(!key_depends_on_user_input(&concrete_key));
    }

    #[test]
    fn test_trace_has_jumpi_guard_detects_visited_jumpi_pc() {
        let bytecode = Bytes::from(vec![0x60, 0x57, 0x00]);
        let mut visited = HashMap::new();
        visited.insert(1usize, 1usize);

        assert!(trace_has_jumpi_guard(&bytecode, &visited));
    }

    #[test]
    fn test_has_polynomial_invariant_violation_detects_drop() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let slot_a = BV::from_u64(&ctx, 0, 256);
        let slot_b = BV::from_u64(&ctx, 1, 256);
        let k_before =
            crate::symbolic::utils::math::extend_to_512(&ctx, &BV::from_u64(&ctx, 100, 256));
        let k_after =
            crate::symbolic::utils::math::extend_to_512(&ctx, &BV::from_u64(&ctx, 81, 256));
        let trace = PolynomialInvariantTrace {
            call_data: Bytes::new(),
            success_execution: true,
            reverted: false,
            slot_a: slot_a.clone(),
            slot_b: slot_b.clone(),
            abstract_constraints: build_abstract_slot_pair_constraints(&ctx, &slot_a, &slot_b),
            storage_writes: vec![
                (BV::from_u64(&ctx, 0, 256), BV::from_u64(&ctx, 11, 256)),
                (BV::from_u64(&ctx, 1, 256), BV::from_u64(&ctx, 7, 256)),
            ],
            k_before,
            k_after,
        };

        assert!(has_polynomial_invariant_violation(&ctx, &solver, &trace));
    }

    #[test]
    fn test_selected_slot_touched_constraint_detects_slot_zero() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let writes = vec![(BV::from_u64(&ctx, 0, 256), BV::from_u64(&ctx, 123, 256))];
        let slot = BV::from_u64(&ctx, 0, 256);
        let touched = selected_slot_touched_constraint(&ctx, &writes, &slot)
            .expect("touched-slot formula must exist for non-empty writes");

        solver.push();
        solver.assert(&touched);
        assert_eq!(solver.check(), z3::SatResult::Sat);
        solver.pop(1);
    }

    #[test]
    fn test_constrained_positive_balance_rejects_zero_and_above_cap() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let upper = BV::from_u64(&ctx, 100, 256);

        solver.push();
        let zero_case = BV::from_u64(&ctx, 0, 256);
        solver.assert(&constrained_positive_balance(&ctx, &zero_case, &upper));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
        solver.pop(1);

        solver.push();
        let overflow_case = BV::from_u64(&ctx, 101, 256);
        solver.assert(&constrained_positive_balance(&ctx, &overflow_case, &upper));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
        solver.pop(1);
    }

    #[test]
    fn test_constrained_positive_balance_accepts_in_range() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let upper = BV::from_u64(&ctx, 100, 256);
        let valid = BV::from_u64(&ctx, 73, 256);
        solver.assert(&constrained_positive_balance(&ctx, &valid, &upper));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_hook_settlement_manipulation_detects_post_hook_write() {
        let trace = UniV4HookTrace {
            success_execution: true,
            reverted: false,
            reentrancy_detected: false,
            self_destructed: false,
            storage_writes_len: 3,
            created_contracts_len: 0,
            hook_calls: vec![HookCall {
                target: Address::new([0x11; 20]),
                selector: 0xdeadbeef,
                call_site_pc: 42,
                is_static: false,
                storage_log_len_at_call: 1,
            }],
        };
        assert!(has_settlement_manipulation(&trace));
    }

    #[test]
    fn test_hook_settlement_manipulation_rejects_no_post_hook_delta() {
        let trace = UniV4HookTrace {
            success_execution: true,
            reverted: false,
            reentrancy_detected: false,
            self_destructed: false,
            storage_writes_len: 1,
            created_contracts_len: 0,
            hook_calls: vec![HookCall {
                target: Address::new([0x22; 20]),
                selector: 0xfeedface,
                call_site_pc: 64,
                is_static: false,
                storage_log_len_at_call: 1,
            }],
        };
        assert!(!has_settlement_manipulation(&trace));
    }

    #[test]
    fn test_hook_reentrancy_requires_hook_interaction() {
        let with_hook = UniV4HookTrace {
            success_execution: true,
            reverted: false,
            reentrancy_detected: true,
            self_destructed: false,
            storage_writes_len: 0,
            created_contracts_len: 0,
            hook_calls: vec![HookCall {
                target: Address::new([0x33; 20]),
                selector: 0xabcdef01,
                call_site_pc: 12,
                is_static: false,
                storage_log_len_at_call: 0,
            }],
        };
        let without_hook = UniV4HookTrace {
            success_execution: true,
            reverted: false,
            reentrancy_detected: true,
            self_destructed: false,
            storage_writes_len: 0,
            created_contracts_len: 0,
            hook_calls: vec![],
        };
        assert!(has_hook_reentrancy(&with_hook));
        assert!(!has_hook_reentrancy(&without_hook));
    }

    #[test]
    fn test_erc4626_violation_sat_detects_share_price_drop() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let state = Erc4626VaultState {
            initial_assets: BV::from_u64(&ctx, 100, 256),
            initial_supply: BV::from_u64(&ctx, 100, 256),
            current_assets: BV::from_u64(&ctx, 90, 256),
            current_supply: BV::from_u64(&ctx, 100, 256),
            touched: true,
        };

        assert!(erc4626_violation_sat(&ctx, &solver, &state));
    }

    #[test]
    fn test_erc4626_violation_sat_rejects_non_decreasing_ratio() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let state = Erc4626VaultState {
            initial_assets: BV::from_u64(&ctx, 100, 256),
            initial_supply: BV::from_u64(&ctx, 100, 256),
            current_assets: BV::from_u64(&ctx, 110, 256),
            current_supply: BV::from_u64(&ctx, 100, 256),
            touched: true,
        };

        assert!(!erc4626_violation_sat(&ctx, &solver, &state));
    }

    #[test]
    fn test_run_with_z3_solver_reuses_sticky_context_per_thread() {
        let mut first_ptr = 0usize;
        let _ = run_with_z3_solver(|ctx, _solver| {
            first_ptr = ctx as *const Context as usize;
            None
        });
        let mut second_ptr = 0usize;
        let _ = run_with_z3_solver(|ctx, _solver| {
            second_ptr = ctx as *const Context as usize;
            None
        });

        assert_ne!(first_ptr, 0);
        assert_eq!(first_ptr, second_ptr);
    }

    #[test]
    fn test_run_with_z3_solver_resets_assertions_between_calls() {
        let _ = run_with_z3_solver(|ctx, solver| {
            assert!(solver.get_assertions().is_empty());
            let one = BV::from_u64(ctx, 1, 256);
            solver.assert(&one._eq(&one));
            assert_eq!(solver.get_assertions().len(), 1);
            None
        });
        let _ = run_with_z3_solver(|_ctx, solver| {
            assert!(
                solver.get_assertions().is_empty(),
                "sticky solver must be reset between objective invocations"
            );
            None
        });
    }

    #[test]
    fn test_choose_primary_flash_loan_source_prefers_lowest_fee_provider() {
        let fallback_token = Address::new([0x44; 20]);
        let legs = vec![
            FlashLoanLeg {
                provider: Address::new([0x02; 20]),
                token: Address::new([0x22; 20]),
                amount: U256::from(5u64),
                fee_bps: 9,
            },
            FlashLoanLeg {
                provider: Address::new([0x01; 20]),
                token: Address::new([0x33; 20]),
                amount: U256::from(5u64),
                fee_bps: 0,
            },
        ];

        let chosen = choose_primary_flash_loan_source(&legs, fallback_token)
            .expect("expected a primary source for non-empty legs");
        assert_eq!(chosen.0, Address::new([0x01; 20]));
        assert_eq!(chosen.1, Address::new([0x33; 20]));
    }

    #[test]
    fn test_choose_primary_flash_loan_source_uses_fallback_for_zero_token() {
        let fallback_token = Address::new([0x77; 20]);
        let legs = vec![FlashLoanLeg {
            provider: Address::new([0xAA; 20]),
            token: Address::ZERO,
            amount: U256::from(1u64),
            fee_bps: 0,
        }];

        let chosen = choose_primary_flash_loan_source(&legs, fallback_token)
            .expect("expected a primary source for non-empty legs");
        assert_eq!(chosen, (Address::new([0xAA; 20]), fallback_token));
    }
}

// End of Objectives
