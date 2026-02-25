use alloy::hex;
use revm::primitives::Bytes;

/// ANCHOR TEST: STATE POLLUTION
/// PROOVES: The symbolic engine fails to isolate concrete DB state during backtracking.
/// SCENARIO:
/// 1. Path A (executed first) writes 1 to storage slot 0.
/// 2. Path A fails profit check and backtracks.
/// 3. Path B (executed second) reads storage slot 0.
/// 4. Path B sees 1 (pollution from A) and falsely triggers profit.
#[tokio::test(flavor = "multi_thread")]
async fn test_state_pollution_false_positive() {
    // 6000     PUSH1 0
    // 35       CALLDATALOAD (Input)
    // 6000     PUSH1 0
    // 14       EQ
    // 600e     PUSH1 14 (Jump to READ)
    // 57       JUMPI

    // FALLTHROUGH (Input != 0) -> WRITE 1
    // Offset 9
    // 6001     PUSH1 1
    // 6000     PUSH1 0
    // 55       SSTORE
    // 00       STOP

    // JUMPDEST (Input == 0) -> READ & CHECK 1
    // Offset 14 (0x0e)
    // 5b       JUMPDEST
    // 6000     PUSH1 0
    // 54       SLOAD
    // 6001     PUSH1 1
    // 14       EQ
    // 6019     PUSH1 25 (Jump to PROFIT)
    // 57       JUMPI
    // 00       STOP

    // PROFIT
    // Offset 25 (0x19)
    // 5b       JUMPDEST
    // 33       CALLER
    // 47       SELFBALANCE
    // 90       SWAP1
    // 6000     PUSH1 0
    // 90       SWAP1
    // 6000     PUSH1 0
    // 81       DUP2 (0, 0, amount, 0)
    // 81       DUP2 (0, 0, 0, amount, 0)
    // 81       DUP2 (0, 0, 0, 0, amount, 0)
    // 33       CALLER
    // 5a       GAS
    // f1       CALL

    // If state is clean, READ sees 0. 0 != 1. No jump to profit.
    // If state is polluted, READ sees 1. 1 == 1. Jump to profit.

    // Code: 600035600014600e576001600055005b600054600114601957005b3347906000906000818181335af1
    let bytecode_hex =
        "600035600014600e576001600055005b600054600114601957005b3347906000906000818181335af1";
    let bytes = Bytes::from(hex::decode(bytecode_hex).unwrap());

    // Mock Objective
    // We assume the engine will try to maximize profit.
    // We rely on "Generic Invariant Breach" which checks balance > initial.
    // The bytecode sends FULL BALANCE to caller if condition met.

    // Custom Execution Logic to Avoid RPC (init_tokens)
    use dark_solver::solver::objectives::{run_with_z3_solver, solve_market_invariant};
    use dark_solver::solver::setup::StandardScenario;

    let result = run_with_z3_solver(|ctx, solver| {
        let rpc_url = "http://localhost:8545".to_string();

        let mut scenario =
            StandardScenario::try_new(ctx, solver, &rpc_url, &bytes, "flash_loan_amount")
                .expect("scenario init");

        // Skip init_tokens to avoid RPC calls
        let initial_token_vars = vec![];

        // Mock Attacker for Gas Check
        let attacker_info = revm::primitives::AccountInfo {
            balance: revm::primitives::U256::MAX,
            nonce: 0,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        };
        scenario
            .db
            .insert_account_info(scenario.attacker, attacker_info);

        scenario.constrain_loan(solver, "1000000000000000000000000");

        // 0. Dynamic Selector Discovery
        let mut selectors = vec![
            Bytes::new(),
            Bytes::from_static(&dark_solver::utils::selectors::WITHDRAW),
            Bytes::from_static(&dark_solver::utils::selectors::CLAIM),
        ];

        // No Scan for selectors (avoids heurstics)
        selectors.sort();
        selectors.dedup();

        // Reduced depth to 1 (Single Transaction is enough to prove state pollution)
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
            1,
            &selectors,
            &initial_token_vars,
        )
    });

    // ASSERT
    if let Some(exploit) = result {
        println!("Unexpected finding after rewind check: {:?}", exploit);
        panic!("False positive detected: engine failed to rewind concrete DB state.");
    } else {
        println!("PASS: No exploit found (State isolation working).");
    }
}
