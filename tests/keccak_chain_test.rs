use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::{bv_from_u256, u256_from_bv};
use revm::primitives::{keccak256, U256};
use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};

// Helper for concrete keccak
fn keccak_64(a: U256, b: U256) -> U256 {
    let mut input = [0u8; 64];
    input[0..32].copy_from_slice(&a.to_be_bytes::<32>());
    input[32..64].copy_from_slice(&b.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(input).0)
}

#[test]
fn test_deep_keccak_chain_resolution() {
    // 1. Setup Z3 & Machine
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // 2. Define Concrete Constants FIRST
    let base_slot = U256::from(0);
    let target_k1 = U256::from(0xAAAA);
    let target_k2 = U256::from(0xBBBB);
    let target_k3 = U256::from(0xCCCC);

    // 3. Compute Expected Concrete Hashes (The "Oracle" Knowledge)
    let c_s1 = keccak_64(target_k1, base_slot);
    let c_s2 = keccak_64(target_k2, c_s1);
    let c_s3 = keccak_64(target_k3, c_s2);

    // 4. Convert to BVs for Oracle Population
    let base_slot_bv = bv_from_u256(&ctx, base_slot);
    let c_s1_bv = bv_from_u256(&ctx, c_s1);
    let c_s2_bv = bv_from_u256(&ctx, c_s2);
    let c_s3_bv = bv_from_u256(&ctx, c_s3);

    let target_k1_bv = bv_from_u256(&ctx, target_k1);
    let target_k2_bv = bv_from_u256(&ctx, target_k2);
    let target_k3_bv = bv_from_u256(&ctx, target_k3);

    // 5. Populate Oracle Preimage Map
    // This tells Z3: "If you see Hash X, its preimage is (Key, Slot)"
    machine
        .oracle
        .preimage_map
        .insert(c_s1, vec![target_k1_bv.clone(), base_slot_bv.clone()]);
    machine
        .oracle
        .preimage_map
        .insert(c_s2, vec![target_k2_bv.clone(), c_s1_bv.clone()]);
    machine
        .oracle
        .preimage_map
        .insert(c_s3, vec![target_k3_bv.clone(), c_s2_bv.clone()]);

    // 6. Register Base Pattern (Forward Reasoning Anchor)
    // We tell the machine that `base_slot` (0) is a FlatMapping root.
    machine.detected_patterns.insert(
        base_slot,
        dark_solver::symbolic::patterns::StoragePattern::FlatMapping(base_slot, None),
    );

    // 7. Initialize Symbolic Variables
    let k1 = BV::new_const(&ctx, "k1", 256);
    let k2 = BV::new_const(&ctx, "k2", 256);
    let k3 = BV::new_const(&ctx, "k3", 256);

    // 8. Record Traces (Simulating Execution)
    // Level 1
    let s1 = machine
        .keccak
        .keccak_256_64
        .apply(&[&k1, &base_slot_bv])
        .as_bv()
        .unwrap();
    let trace1 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![k1.clone(), base_slot_bv.clone()],
        hash: s1.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 10,
    };
    machine.record_sha3(trace1);

    // Level 2
    let s2 = machine
        .keccak
        .keccak_256_64
        .apply(&[&k2, &s1])
        .as_bv()
        .unwrap();
    let trace2 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![k2.clone(), s1.clone()],
        hash: s2.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 20,
    };
    machine.record_sha3(trace2);

    // Level 3
    let s3 = machine
        .keccak
        .keccak_256_64
        .apply(&[&k3, &s2])
        .as_bv()
        .unwrap();
    let trace3 = dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![k3.clone(), s2.clone()],
        hash: s3.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 30,
    };
    machine.record_sha3(trace3);

    // 9. Assert Goal
    solver.assert(&s3._eq(&c_s3_bv));

    // 10. Solve
    println!("Solving for keys...");
    let result = solver.check();
    assert_eq!(result, z3::SatResult::Sat, "Solver should be SAT");

    let model = solver.get_model().unwrap();
    let k1_sol = u256_from_bv(&model.eval(&k1, true).unwrap()).unwrap();
    let k2_sol = u256_from_bv(&model.eval(&k2, true).unwrap()).unwrap();
    let k3_sol = u256_from_bv(&model.eval(&k3, true).unwrap()).unwrap();

    println!("Found Keys:");
    println!("K1: {:?} (Expected: {:?})", k1_sol, target_k1);
    println!("K2: {:?} (Expected: {:?})", k2_sol, target_k2);
    println!("K3: {:?} (Expected: {:?})", k3_sol, target_k3);

    assert_eq!(k1_sol, target_k1, "K1 mismatch");
    assert_eq!(k2_sol, target_k2, "K2 mismatch");
    assert_eq!(k3_sol, target_k3, "K3 mismatch");
}
