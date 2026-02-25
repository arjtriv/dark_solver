const DEEP_INVARIANT_DEFAULT_MAX_DEPTH: usize = 10;
const DEEP_INVARIANT_MAX_DEPTH_CAP: usize = 16;
const DEEP_INVARIANT_DEFAULT_MAX_SELECTORS: usize = 24;
const DEEP_INVARIANT_MAX_SELECTORS_CAP: usize = 64;

fn load_deep_invariant_max_depth() -> usize {
    std::env::var("DEEP_INVARIANT_MAX_DEPTH")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(DEEP_INVARIANT_MAX_DEPTH_CAP))
        .unwrap_or(DEEP_INVARIANT_DEFAULT_MAX_DEPTH)
}

fn load_deep_invariant_max_selectors() -> usize {
    std::env::var("DEEP_INVARIANT_MAX_SELECTORS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(DEEP_INVARIANT_MAX_SELECTORS_CAP))
        .unwrap_or(DEEP_INVARIANT_DEFAULT_MAX_SELECTORS)
}

/// Phase 3: Deep Invariant Analysis (10-Hop)
/// Runs a deeper multi-step search than Tier-1 objectives. Intended for background queue execution.
pub struct DeepInvariantAnalysisObjective {
    pub rpc_url: String,
    pub chain_id: u64,
}

impl ExploitObjective for DeepInvariantAnalysisObjective {
    fn name(&self) -> &str {
        "Deep Invariant Analysis (10-Hop)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();

            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "deep_invariant_flash_loan_amount",
            )
            .ok()?;

            let initial_token_vars = scenario.init_tokens(self.chain_id, bytecode);
            scenario.constrain_loan(solver, "1000000000000000000000000");

            let mut selectors = vec![
                Bytes::new(),
                Bytes::from_static(&crate::utils::selectors::WITHDRAW),
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

            // Respect UNSAT memoization (hot-path uses this too); do not add new UNSAT entries here.
            let mut selectors: Vec<Bytes> = selectors
                .into_iter()
                .filter(|sel| {
                    !matches!(
                        crate::solver::memo::lookup(bytecode, sel),
                        Some(crate::solver::memo::ProofResult::Unsat)
                    )
                })
                .collect();

            let max_selectors = load_deep_invariant_max_selectors();
            if selectors.len() > max_selectors {
                selectors.truncate(max_selectors);
            }

            let max_depth = load_deep_invariant_max_depth();
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
                max_depth,
                &selectors,
                &initial_token_vars,
            )
        })
    }
}

impl ExploitObjective for DelegateeHijackObjective {
    fn name(&self) -> &str {
        "Delegation Control Reassignment Risk"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        if !crate::protocols::governance::has_delegatee_hijack_pattern(bytecode) {
            return None;
        }

        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "delegatee_hijack_loan",
            )
            .ok()?;

            let mut selectors: Vec<Bytes> =
                crate::protocols::governance::known_delegatee_hijack_selectors()
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

            let owner_word = BV::new_const(ctx, "delegatee_owner_word", 256);
            let caller_word = BV::new_const(ctx, "delegatee_caller_word", 256);
            let delegatee_word = BV::new_const(ctx, "delegatee_target_word", 256);
            let votes_before = BV::new_const(ctx, "delegatee_votes_before", 256);
            let votes_after = BV::new_const(ctx, "delegatee_votes_after", 256);

            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from_be_bytes(scenario.attacker.into_word().into()),
            );

            solver.assert(&votes_before.bvugt(&zero(ctx)));
            solver.assert(&votes_after.bvugt(&zero(ctx)));
            solver.assert(
                &crate::protocols::governance::unauthorized_delegate_to_attacker(
                    ctx,
                    &caller_word,
                    &owner_word,
                    &delegatee_word,
                    &attacker_word,
                    &votes_before,
                    &votes_after,
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
                steps: build_delegatee_hijack_steps(scenario.contract_addr, &selectors),
                expected_profit: Some(U256::from(1u64)),
                block_offsets: None,
            })
        })
    }
}

#[derive(Clone)]
struct SymbolicFuzzTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes_len: usize,
    transfer_events: Vec<TokenTransferEvent<'ctx>>,
}

fn execute_symbolic_fuzz_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> SymbolicFuzzTrace<'ctx> {
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

    let trace = SymbolicFuzzTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes_len: scenario.machine.storage_log.len(),
        transfer_events: scenario.machine.token_transfer_events.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

const SYMBOLIC_FUZZ_STORAGE_WRITE_THRESHOLD: usize = 5;

fn symbolic_fuzz_token_print_threshold() -> U256 {
    // 1,000,000 tokens in 18-decimal base units.
    U256::from(1_000_000u64).saturating_mul(U256::from(10u64).pow(U256::from(18u64)))
}

fn has_symbolic_fuzz_anomaly<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    attacker: Address,
    trace: &SymbolicFuzzTrace<'ctx>,
) -> bool {
    if trace.reverted || !trace.success_execution {
        return false;
    }

    if trace.storage_writes_len > SYMBOLIC_FUZZ_STORAGE_WRITE_THRESHOLD {
        return true;
    }

    let print_threshold =
        crate::symbolic::z3_ext::bv_from_u256(ctx, symbolic_fuzz_token_print_threshold());
    for event in &trace.transfer_events {
        if event.to != attacker {
            continue;
        }

        solver.push();
        solver.assert(&event.received_amount.bvugt(&print_threshold));
        let sat = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if sat {
            return true;
        }
    }

    false
}

/// Strategy 8: Symbolic Fuzzing (Invariant-Free Exploration)
/// Flags high-entropy state anomalies even when explicit profit constraints are absent.
pub struct SymbolicFuzzingObjective {
    pub rpc_url: String,
}

impl ExploitObjective for SymbolicFuzzingObjective {
    fn name(&self) -> &str {
        "Symbolic Fuzzing (Invariant-Free Exploration)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "symbolic_fuzz_loan",
            )
            .ok()?;

            let mut selectors = vec![Bytes::new()];
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
                let trace = execute_symbolic_fuzz_trace(solver, &mut scenario, call_data);
                if has_symbolic_fuzz_anomaly(ctx, solver, scenario.attacker, &trace) {
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
struct DifferentialConstraintTrace<'ctx> {
    call_data: Bytes,
    success_execution: bool,
    reverted: bool,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
    constraints: Vec<Bool<'ctx>>,
}

fn execute_differential_constraint_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> DifferentialConstraintTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    let base_assertions_len = solver.get_assertions().len();

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

    let constraints = solver
        .get_assertions()
        .into_iter()
        .skip(base_assertions_len)
        .collect::<Vec<_>>();

    let trace = DifferentialConstraintTrace {
        call_data: call_data.clone(),
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes: scenario.machine.storage_log.clone(),
        constraints,
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn conjunct_constraints<'ctx>(ctx: &'ctx Context, constraints: &[Bool<'ctx>]) -> Bool<'ctx> {
    if constraints.is_empty() {
        return Bool::from_bool(ctx, true);
    }
    let refs = constraints.iter().collect::<Vec<_>>();
    Bool::and(ctx, &refs)
}

fn constraint_implies<'ctx>(
    solver: &'ctx Solver<'ctx>,
    lhs: &Bool<'ctx>,
    rhs: &Bool<'ctx>,
) -> bool {
    solver.push();
    solver.assert(lhs);
    solver.assert(&rhs.not());
    let implies = solver.check() == z3::SatResult::Unsat;
    solver.pop(1);
    implies
}

fn same_slot_possible<'ctx>(
    solver: &'ctx Solver<'ctx>,
    lhs_key: &BV<'ctx>,
    rhs_key: &BV<'ctx>,
) -> bool {
    solver.push();
    solver.assert(&lhs_key._eq(rhs_key));
    let sat = solver.check() == z3::SatResult::Sat;
    solver.pop(1);
    sat
}

fn has_differential_constraint_gap<'ctx>(
    solver: &'ctx Solver<'ctx>,
    c1: &Bool<'ctx>,
    c2: &Bool<'ctx>,
) -> bool {
    constraint_implies(solver, c1, c2) && !constraint_implies(solver, c2, c1)
}

const DIFFERENTIAL_MAX_SELECTORS: usize = 5;
const DIFFERENTIAL_MAX_WRITES_PER_TRACE: usize = 3;

/// Strategy 9: Differential Constraint Analysis (Logic Gap)
/// Detects implication asymmetry where one selector's write-guard is strictly weaker.
pub struct DifferentialConstraintObjective {
    pub rpc_url: String,
}

impl ExploitObjective for DifferentialConstraintObjective {
    fn name(&self) -> &str {
        "Differential Constraint Analysis"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "differential_constraint_loan",
            )
            .ok()?;

            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            selectors.sort();
            selectors.dedup();
            if selectors.len() < 2 {
                return None;
            }
            selectors.truncate(selectors.len().min(DIFFERENTIAL_MAX_SELECTORS));

            let mut traces = Vec::new();
            for call_data in &selectors {
                let mut trace =
                    execute_differential_constraint_trace(solver, &mut scenario, call_data);
                if trace.reverted || !trace.success_execution || trace.storage_writes.is_empty() {
                    continue;
                }
                trace.storage_writes.truncate(
                    trace
                        .storage_writes
                        .len()
                        .min(DIFFERENTIAL_MAX_WRITES_PER_TRACE),
                );
                traces.push(trace);
            }

            if traces.len() < 2 {
                return None;
            }

            for i in 0..traces.len() {
                for j in 0..traces.len() {
                    if i == j {
                        continue;
                    }

                    let c1 = conjunct_constraints(ctx, &traces[i].constraints);
                    let c2 = conjunct_constraints(ctx, &traces[j].constraints);
                    if !has_differential_constraint_gap(solver, &c1, &c2) {
                        continue;
                    }

                    for (lhs_key, _) in &traces[i].storage_writes {
                        for (rhs_key, _) in &traces[j].storage_writes {
                            if !same_slot_possible(solver, lhs_key, rhs_key) {
                                continue;
                            }

                            return Some(ExploitParams {
                                flash_loan_amount: U256::ZERO,
                                flash_loan_token: Address::ZERO,
                                flash_loan_provider: Address::ZERO,
                                flash_loan_legs: Vec::new(),
                                steps: vec![
                                    ExploitStep {
                                        target: scenario.contract_addr,
                                        call_data: traces[i].call_data.clone(),
                                        execute_if: None,
                                    },
                                    ExploitStep {
                                        target: scenario.contract_addr,
                                        call_data: traces[j].call_data.clone(),
                                        execute_if: None,
                                    },
                                ],
                                expected_profit: Some(U256::from(1u64)),
                                block_offsets: None,
                            });
                        }
                    }
                }
            }

            None
        })
    }
}

#[derive(Clone)]
struct StateTransitionTrace<'ctx> {
    call_data: Bytes,
    success_execution: bool,
    reverted: bool,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
    transfer_events: Vec<TokenTransferEvent<'ctx>>,
}

#[derive(Clone)]
struct StateTransitionEdge {
    from: usize,
    to: usize,
    call_data: Bytes,
    positive_balance: bool,
}

const STG_UNPRIVILEGED: usize = 0;
const STG_PRIVILEGED: usize = 1;
const STG_MAX_SELECTORS: usize = 6;

fn execute_state_transition_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> StateTransitionTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.storage_log.clear();
    scenario.machine.token_transfer_events.clear();

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

    let trace = StateTransitionTrace {
        call_data: call_data.clone(),
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes: scenario.machine.storage_log.clone(),
        transfer_events: scenario.machine.token_transfer_events.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn has_low_slot_owner_demotion<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    storage_writes: &[(BV<'ctx>, BV<'ctx>)],
    attacker_word: &BV<'ctx>,
) -> bool {
    if storage_writes.is_empty() {
        return false;
    }

    for (slot, value) in storage_writes {
        let slot_match = owner_slot_in_range(ctx, slot);

        solver.push();
        solver.assert(&slot_match);
        solver.assert(&value._eq(attacker_word).not());
        let sat_not_attacker = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if !sat_not_attacker {
            continue;
        }

        solver.push();
        solver.assert(&slot_match);
        solver.assert(&value._eq(attacker_word));
        let sat_attacker = solver.check() == z3::SatResult::Sat;
        solver.pop(1);

        if !sat_attacker {
            return true;
        }
    }

    false
}

fn has_positive_attacker_receipt<'ctx>(
    ctx: &'ctx Context,
    solver: &'ctx Solver<'ctx>,
    attacker: Address,
    transfer_events: &[TokenTransferEvent<'ctx>],
) -> bool {
    let zero = crate::symbolic::utils::math::zero(ctx);

    for event in transfer_events {
        if event.to != attacker {
            continue;
        }
        solver.push();
        solver.assert(&event.received_amount.bvugt(&zero));
        let sat = solver.check() == z3::SatResult::Sat;
        solver.pop(1);
        if sat {
            return true;
        }
    }

    false
}

fn tarjan_scc(node_count: usize, edges: &[(usize, usize)]) -> Vec<Vec<usize>> {
    struct TarjanState<'a> {
        index: usize,
        indices: Vec<usize>,
        lowlink: Vec<usize>,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        components: Vec<Vec<usize>>,
        graph: &'a [Vec<usize>],
    }

    let mut graph = vec![Vec::<usize>::new(); node_count];
    for (from, to) in edges {
        if *from < node_count && *to < node_count {
            graph[*from].push(*to);
        }
    }

    fn strong_connect(node: usize, state: &mut TarjanState<'_>) {
        state.indices[node] = state.index;
        state.lowlink[node] = state.index;
        state.index += 1;
        state.stack.push(node);
        state.on_stack[node] = true;

        for &neighbor in &state.graph[node] {
            if state.indices[neighbor] == usize::MAX {
                strong_connect(neighbor, state);
                state.lowlink[node] = state.lowlink[node].min(state.lowlink[neighbor]);
            } else if state.on_stack[neighbor] {
                state.lowlink[node] = state.lowlink[node].min(state.indices[neighbor]);
            }
        }

        if state.lowlink[node] == state.indices[node] {
            let mut component = Vec::new();
            while let Some(w) = state.stack.pop() {
                state.on_stack[w] = false;
                component.push(w);
                if w == node {
                    break;
                }
            }
            state.components.push(component);
        }
    }

    let mut state = TarjanState {
        index: 0,
        indices: vec![usize::MAX; node_count],
        lowlink: vec![0usize; node_count],
        stack: Vec::<usize>::new(),
        on_stack: vec![false; node_count],
        components: Vec::<Vec<usize>>::new(),
        graph: &graph,
    };

    for node in 0..node_count {
        if state.indices[node] == usize::MAX {
            strong_connect(node, &mut state);
        }
    }

    state.components
}

/// Strategy 10: State Transition Graph (STG) Cycle Detection
/// Searches for Unprivileged -> Privileged -> Unprivileged cycles with positive attacker inflow.
pub struct StateTransitionCycleObjective {
    pub rpc_url: String,
}

impl ExploitObjective for StateTransitionCycleObjective {
    fn name(&self) -> &str {
        "State Transition Graph Cycle Detection"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "stg_cycle_loan",
            )
            .ok()?;

            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            selectors.sort();
            selectors.dedup();
            if selectors.is_empty() {
                return None;
            }
            selectors.truncate(selectors.len().min(STG_MAX_SELECTORS));

            let attacker_word = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from_be_bytes(scenario.attacker.into_word().into()),
            );

            let mut edges = Vec::<StateTransitionEdge>::new();
            for call_data in &selectors {
                let trace = execute_state_transition_trace(solver, &mut scenario, call_data);
                if trace.reverted || !trace.success_execution {
                    continue;
                }

                let takeover =
                    has_low_slot_owner_takeover(ctx, solver, &trace.storage_writes, &attacker_word);
                let demotion =
                    has_low_slot_owner_demotion(ctx, solver, &trace.storage_writes, &attacker_word);

                if !takeover && !demotion {
                    continue;
                }

                let positive_balance = has_positive_attacker_receipt(
                    ctx,
                    solver,
                    scenario.attacker,
                    &trace.transfer_events,
                );

                if takeover {
                    edges.push(StateTransitionEdge {
                        from: STG_UNPRIVILEGED,
                        to: STG_PRIVILEGED,
                        call_data: trace.call_data.clone(),
                        positive_balance,
                    });
                }
                if demotion {
                    edges.push(StateTransitionEdge {
                        from: STG_PRIVILEGED,
                        to: STG_UNPRIVILEGED,
                        call_data: trace.call_data,
                        positive_balance,
                    });
                }
            }

            if edges.len() < 2 {
                return None;
            }

            let edge_pairs = edges.iter().map(|e| (e.from, e.to)).collect::<Vec<_>>();
            let components = tarjan_scc(2, &edge_pairs);

            for component in components {
                let contains_cycle_pair =
                    component.contains(&STG_UNPRIVILEGED) && component.contains(&STG_PRIVILEGED);
                if !contains_cycle_pair {
                    continue;
                }

                let mut up_edge: Option<&StateTransitionEdge> = None;
                let mut down_edge: Option<&StateTransitionEdge> = None;
                let mut has_positive = false;
                for edge in &edges {
                    if !component.contains(&edge.from) || !component.contains(&edge.to) {
                        continue;
                    }
                    if edge.from == STG_UNPRIVILEGED
                        && edge.to == STG_PRIVILEGED
                        && up_edge.is_none()
                    {
                        up_edge = Some(edge);
                    }
                    if edge.from == STG_PRIVILEGED
                        && edge.to == STG_UNPRIVILEGED
                        && down_edge.is_none()
                    {
                        down_edge = Some(edge);
                    }
                    has_positive |= edge.positive_balance;
                }

                if let (Some(up), Some(down)) = (up_edge, down_edge) {
                    if has_positive {
                        return Some(ExploitParams {
                            flash_loan_amount: U256::ZERO,
                            flash_loan_token: Address::ZERO,
                            flash_loan_provider: Address::ZERO,
                            flash_loan_legs: Vec::new(),
                            steps: vec![
                                ExploitStep {
                                    target: scenario.contract_addr,
                                    call_data: up.call_data.clone(),
                                    execute_if: None,
                                },
                                ExploitStep {
                                    target: scenario.contract_addr,
                                    call_data: down.call_data.clone(),
                                    execute_if: None,
                                },
                            ],
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
struct TaintFlowTrace<'ctx> {
    success_execution: bool,
    reverted: bool,
    storage_writes: Vec<(BV<'ctx>, BV<'ctx>)>,
    visited_pcs: HashMap<usize, usize>,
}

fn execute_taint_flow_trace<'ctx>(
    solver: &'ctx Solver<'ctx>,
    scenario: &mut crate::solver::setup::StandardScenario<'ctx>,
    call_data: &Bytes,
) -> TaintFlowTrace<'ctx> {
    let snapshot = scenario.machine.snapshot();
    let mut current_db = scenario.db.clone();
    solver.push();

    scenario.machine.reset_calldata();
    scenario.machine.tx_id += 1;
    scenario.machine.reverted = false;
    scenario.machine.storage_log.clear();
    scenario.machine.clear_visited_pcs();

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

    let trace = TaintFlowTrace {
        success_execution,
        reverted: scenario.machine.reverted,
        storage_writes: scenario.machine.storage_log.clone(),
        visited_pcs: scenario.machine.visited_pcs.clone(),
    };

    scenario.machine.restore(&snapshot);
    solver.pop(1);
    trace
}

fn key_depends_on_user_input<'ctx>(key: &BV<'ctx>) -> bool {
    let repr = key.to_string();
    repr.contains("calldata") || repr.contains("caller") || repr.contains("tx_origin")
}

fn trace_has_jumpi_guard(bytecode: &Bytes, visited_pcs: &HashMap<usize, usize>) -> bool {
    visited_pcs
        .keys()
        .any(|pc| bytecode.get(*pc).copied() == Some(0x57))
}

/// Strategy 11: Taint-Flow Storage Corruption
/// Flags storage writes where key taint depends on user input without any JUMPI guard.
pub struct TaintFlowStorageCorruptionObjective {
    pub rpc_url: String,
}
