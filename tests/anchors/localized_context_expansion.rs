//! Anchor: Localized Context Expansion wires dependency context into CacheDB + symbolic storage.

use dark_solver::solver::setup::{
    enter_target_context, DependencyContext, StandardScenario, TargetContext, TARGET,
};
use revm::primitives::{AccountInfo, Address, Bytecode, Bytes, U256};
use revm::Database;
use std::collections::HashSet;
use std::sync::Arc;
use z3::{Config, Context, Solver};

#[test]
fn localized_context_expansion_prewarms_dependency_accounts_and_storage() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let target_bytecode = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00]);
    let target_code = Bytecode::new_raw(target_bytecode.clone());
    let target_info = AccountInfo::new(
        U256::from(1_000u64),
        1,
        target_code.hash_slow(),
        target_code,
    );

    let dep = Address::new([0xDD; 20]);
    let dep_bytes = Bytes::from_static(&[0x60, 0x00, 0x00]);
    let dep_code = Bytecode::new_raw(dep_bytes.clone());
    let dep_info = AccountInfo::new(U256::from(33u64), 2, dep_code.hash_slow(), dep_code);

    let hydrated = Arc::new(TargetContext {
        target_address: TARGET,
        zero_state: false,
        account_info: target_info,
        storage_slots: Vec::new(),
        attacker_token_balances: Vec::new(),
        selectors: Vec::new(),
        nft_callback_selectors: Vec::new(),
        dead_end_pcs: HashSet::new(),
        dependencies: vec![DependencyContext {
            address: dep,
            account_info: dep_info.clone(),
            storage_slots: vec![(U256::from(9u64), U256::from(7u64))],
        }],
    });

    let _scope = enter_target_context(hydrated);
    let mut scenario = StandardScenario::try_new(
        &ctx,
        &solver,
        "http://localhost:8545",
        &target_bytecode,
        "flash_loan_amount",
    )
    .expect("scenario init");

    let loaded = scenario
        .db
        .basic(dep)
        .expect("dependency cache lookup must succeed")
        .expect("dependency must be inserted");
    assert_eq!(loaded.balance, U256::from(33u64));
    assert_eq!(loaded.nonce, 2);

    let arr = scenario.machine.get_storage(dep);
    let key = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, U256::from(9u64));
    let got = arr
        .select(&key)
        .as_bv()
        .expect("storage array must be BV-typed");
    let got_u256 = dark_solver::symbolic::z3_ext::u256_from_bv(&got).expect("must be concrete");
    assert_eq!(got_u256, U256::from(7u64));
}
