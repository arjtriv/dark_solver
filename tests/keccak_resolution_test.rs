use alloy::primitives::{Address, U256};
use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::{bv_from_u256, u256_from_bv};
use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};

#[test]
fn test_keccak_injectivity_resolution() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // 1. Init Machine (Auto-enforces axioms via new())
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // Setup:
    // Slot 1: keccak(Attacker, 0) -> Value 100.
    // We simulate this being in storage_log.

    let attacker = Address::from([0xAA; 20]);
    let target = BV::new_const(&ctx, "target_addr", 256); // Symbolic Target

    // Construct keys using the machines Sliced UFs (keccak_256_64)
    let zero = BV::from_u64(&ctx, 0, 256);

    // Key A: keccak(Attacker, 0)
    let attacker_bv = bv_from_u256(&ctx, U256::from_be_bytes(attacker.into_word().into()));
    let key_attacker = machine
        .keccak
        .keccak_256_64
        .apply(&[&attacker_bv, &zero])
        .as_bv()
        .unwrap();

    machine.record_sha3(dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![attacker_bv.clone(), zero.clone()],
        hash: key_attacker.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 0,
    });

    // Key T: keccak(Target, 0)
    let key_target = machine
        .keccak
        .keccak_256_64
        .apply(&[&target, &zero])
        .as_bv()
        .unwrap();

    machine.record_sha3(dark_solver::symbolic::patterns::SHA3Trace {
        preimage: vec![target.clone(), zero.clone()],
        hash: key_target.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 0,
    });

    let val_100 = BV::from_u64(&ctx, 100, 256);

    // Push write to log: "Attacker has 100"
    machine.storage_log.push((key_attacker, val_100));

    // Simulate SLOAD(key_target) logic manually:
    // res = ITE(key_log == slot, val_log, default)
    let default = BV::from_u64(&ctx, 0, 256);

    // This is the core logic: Can Z3 determine that key_attacker == key_target implies attacker == target?
    let read_val = machine.storage_log[0]
        .0
        ._eq(&key_target)
        .ite(&machine.storage_log[0].1, &default);

    // --- Positive Test ---
    // Assert: read_val == 100
    solver.push();
    solver.assert(&read_val._eq(&BV::from_u64(&ctx, 100, 256)));

    // This requires: key_attacker == key_target.
    // Due to axioms, this requires: attacker == target.
    // If Z3 finds a model, it MUST set target = attacker.

    let result = solver.check();
    if result != z3::SatResult::Sat {
        println!("Z3 Result: {:?}", result);
        println!("Reason Unknown: {:?}", solver.get_reason_unknown());
    }
    assert_eq!(result, z3::SatResult::Sat, "Should be satisfiable");

    let model = solver.get_model().unwrap();
    let target_sol = model.eval(&target, true).unwrap();
    let attacker_sol = model.eval(&attacker_bv, true).unwrap();

    println!("Target Sol: {:?}", target_sol);
    println!("Attacker Sol: {:?}", attacker_sol);

    assert_eq!(
        u256_from_bv(&target_sol),
        u256_from_bv(&attacker_sol),
        "Target MUST be attacker to read 100"
    );
    solver.pop(1);

    // --- Negative Test ---
    // Assert: target != attacker
    // Assert: read_val == 100
    // Result: UNSAT (Impossible)
    solver.push();
    solver.assert(&target._eq(&attacker_bv).not());
    solver.assert(&read_val._eq(&BV::from_u64(&ctx, 100, 256)));

    assert_eq!(
        solver.check(),
        z3::SatResult::Unsat,
        "Should be impossible to read 100 if target != attacker"
    );
    println!("Axiom Check Passed: Injectivity Holds.");
    solver.pop(1);
}
