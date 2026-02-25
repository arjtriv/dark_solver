use dark_solver::fork_db::ForkDB;
use dark_solver::solver::objectives::solve_market_invariant;
use dark_solver::symbolic::state::SymbolicMachine;
use revm::db::CacheDB;
use revm::primitives::hex::FromHex;
use revm::primitives::{AccountInfo, Address, Bytecode, Bytes, U256};
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[tokio::test(flavor = "multi_thread")]
async fn test_delegatecall_spoofing() {
    // This test must fail if the solver is working correctly.
    // If the test PASSES (i.e., finds an exploit), it means the BUG IS PRESENT.

    // 1. Setup Spoof Target
    let lib_addr_hex = "cccccccccccccccccccccccccccccccccccccccc";
    let attacker_addr_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // 2. Construct Bytecode: DELEGATECALL to Lib with selector `transfer(attacker, 1000)`
    // The solver intercepts `transfer` and updates `Lib` balance.
    // BUT `DELEGATECALL` means `Lib` storage is NOT touched.
    // Result: Solver thinks we have 1000 Lib Tokens. Reality: We have 0.

    // PUSH4 a9059cbb (transfer)
    // PUSH1 0xe0 SHL (shift to get selector)
    // PUSH1 0x00 MSTORE (store selector at 0x00)
    // PUSH20 attacker_addr_hex
    // PUSH1 0x04 MSTORE (store attacker address at 0x04)
    // PUSH2 0x03e8 (1000)
    // PUSH1 0x24 MSTORE (store amount at 0x24)
    // PUSH1 0x00 (ret_size)
    // PUSH1 0x00 (ret_offset)
    // PUSH1 0x44 (args_size: 4 + 32 + 32 = 68)
    // PUSH1 0x00 (args_offset)
    // PUSH20 lib_addr_hex
    // PUSH4 0x0f4240f4 (Gas) -> consume F4! Correct to PUSH gas properly then F4.
    // Use GAS opcode (0x5A) or just PUSH1 0x00 (all gas).
    // Correct sequence: ... PUSH20 lib ... GAS (5A) DELEGATECALL (F4) 00
    let full_hex = format!(
        "63a9059cbb60e01b60005273{}6004526103e8602452600060006044600073{}5af400",
        attacker_addr_hex, lib_addr_hex
    );
    // Note: The original post had `630f4240f400` at the end which looks like correct gas + f4 (DELEGATECALL) + 00 (STOP).
    // Correcting the hex to match the logic described.

    let bytecode = Bytes::from_hex(&full_hex).unwrap();

    // 3. Execution - Manual Setup (No RPC)
    let rpc_url = "http://localhost:8545"; // Dummy

    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let mut machine = SymbolicMachine::new(&ctx, &solver, Some(rpc_url.to_string()));
    let attacker = Address::from_hex(attacker_addr_hex).unwrap();
    let contract_addr = Address::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(); // The contract executing the exploit

    let flash_loan_amount = BV::new_const(&ctx, "flash_loan_amount", 256);
    machine.inject_balance_override(attacker, flash_loan_amount.clone());

    // Manual DB Setup
    let fork_db = ForkDB::new(rpc_url).expect("forkdb init");
    let mut db = CacheDB::new(fork_db);
    let code_obj = Bytecode::new_raw(bytecode.clone());
    let info = AccountInfo::new(U256::from(100), 1, code_obj.hash_slow(), code_obj);
    db.insert_account_info(contract_addr, info);

    // Track Lib balance of Attacker
    let lib_addr = Address::from_hex(lib_addr_hex).unwrap();
    let initial_bal = BV::from_u64(&ctx, 0, 256);
    machine
        .token_balances
        .insert((lib_addr, attacker), initial_bal.clone());

    let initial_token_vars = vec![(lib_addr, initial_bal)];
    let selectors = vec![Bytes::new()];
    let flash_loan_parts: Vec<dark_solver::solver::setup::FlashLoanPart<'_>> = Vec::new();

    // RUN with MAX_DEPTH = 1
    // address(this) should be contract_addr
    let res = solve_market_invariant(
        &ctx,
        &solver,
        &mut machine,
        db,
        &flash_loan_amount,
        &flash_loan_parts,
        attacker,
        contract_addr,
        0,
        1,
        &selectors,
        &initial_token_vars,
    );

    // If the solver is buggy, it thinks we profited Lib tokens via the delegatecall.
    if let Some(exploit) = res {
        panic!(
            "Incorrect result: solver identified DELEGATECALL path as token profit. Finding: {:?}",
            exploit
        );
    }
}
