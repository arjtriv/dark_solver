use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::{bv_from_u256, configure_solver};
use revm::primitives::{Address, U256};
use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};
// Mock interpreter/context structures if needed, or use minimal setup
// We need to construct a minimal Machine loop to drive the opcodes.

#[test]
fn test_algebraic_storage_nested_bypass() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // Setup Context
    let base_slot = U256::from(0); // mapping(address => mapping(uint => uint)) storage map;

    // We want to simulate:
    // map[Alice][123] = 999;
    // Condition: map[SymUser][SymIdx] == 999.
    // Z3 should find SymUser=Alice, SymIdx=123.

    // Step 1: Create Concrete Keys for the "Storage"
    let alice = U256::from(0xAAAA);
    let idx = U256::from(123);
    let val = U256::from(999);

    // Step 2: Simulate EVM Execution to STORE this value using SHA3
    // We need to manually drive the SHA3 + SSTORE mechanism or invoke handle_memory.
    // simpler to manually call `machine.record_sha3` and `machine.storage_strategy.sstore`.

    // Trace 1: keccak(alice . base_slot)
    let alice_bv = bv_from_u256(&ctx, alice);
    let base_bv = bv_from_u256(&ctx, base_slot);
    // Real keccak not needed for symbolic flow if we trust patterns,
    // but we need a hash BV to link them.
    let h1_bv = BV::new_const(&ctx, "h1", 256); // Symbolic Hash representing inner map

    let trace1 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![alice_bv.clone(), base_bv.clone()],
        hash: h1_bv.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 1,
    };
    machine.record_sha3(trace1.clone());

    // Trace 2: keccak(idx . h1)
    let idx_bv = bv_from_u256(&ctx, idx);
    let h2_bv = BV::new_const(&ctx, "h2", 256); // Symbolic Hash representing final slot

    let trace2 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![idx_bv.clone(), h1_bv.clone()],
        hash: h2_bv.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 2,
    };
    machine.record_sha3(trace2.clone());

    // STORE: sstore(h2, val)
    // This should trigger the Algebraic Storage to populate Shadow State
    let val_bv = bv_from_u256(&ctx, val);
    let mut target_addr = Address::default();
    target_addr.0[19] = 0x37; // ends with 37
    target_addr.0[18] = 0x13; // ends with 1337 approx

    {
        let mut strat = machine.storage_strategy.take().unwrap();
        strat.sstore(&machine, target_addr, h2_bv.clone(), val_bv.clone());
        machine.storage_strategy = Some(strat);
    }

    // Step 3: Symbolic Retrieval
    // We want to find a User and Index that yields 999.
    // sym_user, sym_idx
    let sym_user = BV::new_const(&ctx, "sym_user", 256);
    let sym_idx = BV::new_const(&ctx, "sym_idx", 256);

    // We need to generate the Hash chain for these symbolic keys
    // sym_h1 = keccak(sym_user . base)
    // sym_h2 = keccak(sym_idx . sym_h1)

    // Note: Z3's `machine.keccak` theory would usually link these.
    // But applying `record_sha3` forces the link via "Lazy Injectivity" or Pattern Inference.
    // Here we manually create the traces to simulate the EVM calculating these hashes.

    let sym_h1 = BV::new_const(&ctx, "sym_h1", 256);
    let sym_trace1 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![sym_user.clone(), base_bv.clone()],
        hash: sym_h1.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 3,
    };
    machine.record_sha3(sym_trace1);

    let sym_h2 = BV::new_const(&ctx, "sym_h2", 256);
    let sym_trace2 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![sym_idx.clone(), sym_h1.clone()],
        hash: sym_h2.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 4,
    };
    machine.record_sha3(sym_trace2);

    // Step 4: SLOAD(sym_h2)
    // This should return a symbolic value derived from Abstract Array
    let loaded_val = {
        let mut strat = machine.storage_strategy.take().unwrap();
        let res = strat.sload(&machine, target_addr, sym_h2.clone());
        machine.storage_strategy = Some(strat);
        res
    };

    // Assert: loaded_val == 999
    solver.assert(&loaded_val._eq(&val_bv));

    // Check Sat
    assert_eq!(solver.check(), z3::SatResult::Sat);

    // Verify Model
    let model = solver.get_model().unwrap();
    let solved_user = model.eval(&sym_user, true).unwrap();
    let solved_idx = model.eval(&sym_idx, true).unwrap();

    println!("Solved User: {:?}", solved_user);
    println!("Solved Idx: {:?}", solved_idx);

    assert_eq!(solved_user.as_u64(), Some(0xAAAA));
    assert_eq!(solved_idx.as_u64(), Some(123));
}
