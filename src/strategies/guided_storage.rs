use crate::solver::objectives::{
    run_with_z3_solver, solve_market_invariant, ExploitObjective, ExploitParams,
};
use revm::{
    primitives::{Account, Address, Bytes, HashMap, U256},
    Database, DatabaseCommit, Evm,
};
use std::collections::HashSet;

/// Phase 1: Tracing Database Wrapper
/// Captures all storage slots accessed during a concrete execution.
pub struct TracingDB<DB> {
    pub inner: DB,
    pub accessed_slots: HashSet<U256>,
}

impl<DB: Database> TracingDB<DB> {
    pub fn new(inner: DB) -> Self {
        Self {
            inner,
            accessed_slots: HashSet::new(),
        }
    }
}

impl<DB: Database> Database for TracingDB<DB> {
    type Error = DB::Error;

    fn basic(
        &mut self,
        address: Address,
    ) -> Result<Option<revm::primitives::AccountInfo>, Self::Error> {
        self.inner.basic(address)
    }

    fn code_by_hash(
        &mut self,
        code_hash: revm::primitives::B256,
    ) -> Result<revm::primitives::Bytecode, Self::Error> {
        self.inner.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.accessed_slots.insert(index);
        self.inner.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<revm::primitives::B256, Self::Error> {
        self.inner.block_hash(number)
    }
}

impl<DB: Database + DatabaseCommit> DatabaseCommit for TracingDB<DB> {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        self.inner.commit(changes)
    }
}

/// Phase 2: Guided Profit Objective
/// Uses concrete traces to bound the symbolic search space.
pub struct GuidedProfitObjective {
    pub rpc_url: String,
    pub chain_id: u64,
    pub flash_loan_amount_str: String,
}

impl ExploitObjective for GuidedProfitObjective {
    fn name(&self) -> &str {
        "Guided Exploration (Concrete -> Symbolic)"
    }

    fn execute(&self, bytecode: &Bytes) -> Option<ExploitParams> {
        run_with_z3_solver(|ctx, solver| {
            let rpc_url = self.rpc_url.clone();

            // Phase 1: concrete tracing.
            let mut recorded_slots = HashSet::new();

            // Extract selectors
            let mut selectors = crate::solver::setup::selectors_from_context_or_scan(bytecode);
            selectors.sort();
            selectors.dedup();

            // Run a concrete EVM pass for each selector.
            {
                let db = crate::solver::setup::StandardScenario::lightweight_db(&rpc_url, bytecode)
                    .ok()?;
                let contract_addr = crate::solver::setup::TARGET;
                let attacker = crate::solver::setup::ATTACKER;

                for sel in &selectors {
                    let mut tracing_db = TracingDB::new(db.clone());

                    let mut evm = Evm::builder()
                        .with_db(&mut tracing_db)
                        .modify_tx_env(|tx| {
                            tx.caller = attacker;
                            tx.transact_to = revm::primitives::TransactTo::Call(contract_addr);
                            tx.data = sel.clone();
                            tx.gas_limit = 500_000;
                        })
                        .build();

                    let _ = evm.transact_commit();
                    drop(evm); // Drop before reading `tracing_db` to end the mutable borrow.
                    recorded_slots.extend(tracing_db.accessed_slots);
                }
            }
            // ---------------------------------

            // Phase 2: symbolic execution.
            let mut scenario = crate::solver::setup::StandardScenario::try_new(
                ctx,
                solver,
                &rpc_url,
                bytecode,
                "flash_loan_amount",
            )
            .ok()?;

            // SEED THE ORACLE with Phase 1 data
            // We only have slots (hashed keys).
            // We can record them as "Accessed".
            // The symbolic engine might use this to prioritize these slots?
            // Currently KeccakOracle needs preimages.
            // PENDING: Implement Preimage Recorder properly in P5.

            // For now, we proceed.
            // 1.b Token Support using Shared Method
            let initial_token_vars = scenario.init_tokens(self.chain_id, bytecode);

            scenario.constrain_loan(solver, &self.flash_loan_amount_str);

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
                100,
                &selectors,
                &initial_token_vars,
            )
        })
    }
}
