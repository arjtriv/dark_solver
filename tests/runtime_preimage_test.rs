use dark_solver::symbolic::state::SymbolicMachine;
use revm::primitives::{keccak256, U256};
use z3::{
    ast::{Ast, BV},
    Config, Context, Solver,
};

#[test]
fn test_runtime_preimage_flow() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    // Initialize machine (mocking fork URL as None or dummy)
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // 1. Simulate SHA3 execution: "We see concrete input [0xAA, 0xBB]"
    let input = vec![0xAA, 0xBB];
    let hash = keccak256(&input);
    let hash_u256 = U256::from_be_bytes(hash.0);

    // 2. Call the new method (simulating what memory.rs:SHA3 does)
    // We expect this hash to be added to common_slots
    machine
        .oracle
        .record_hash(hash_u256, "test_runtime_sha3".to_string());

    // 3. Verify it's in common_slots
    assert!(
        machine.oracle.resolve_slot(hash_u256).is_some(),
        "Oracle should contain the recorded hash"
    );

    // 4. Simulate SLOAD logic: symbolic slot constrained to equal hash
    // This mirrors the situation where: SLOAD(key) where key came from SHA3(...)
    let slot_sym = BV::new_const(&ctx, "slot_key", 256);
    let hash_bv = dark_solver::symbolic::z3_ext::bv_from_u256(machine.context, hash_u256);

    // Constraint: slot_key == hash
    // In a real execution, this constraint comes from the path or the stack value itself being the SHA3 result.
    solver.push();
    solver.assert(&slot_sym._eq(&hash_bv));

    // 5. Verify the SLOAD lookup loop finds it
    // The SLOAD opcode iterates over `common_slots` and builds an ITE based on equality.
    // We simulate checking if Z3 can find a match.
    let mut found = false;
    for stored_hash in machine.oracle.common_slots.keys() {
        let stored_hash_bv =
            dark_solver::symbolic::z3_ext::bv_from_u256(machine.context, *stored_hash);

        // Check if `slot_sym == stored_hash` is consistent with our constraints
        solver.push();
        solver.assert(&slot_sym._eq(&stored_hash_bv));
        if solver.check() == z3::SatResult::Sat {
            found = true;
        }
        solver.pop(1);
    }

    assert!(
        found,
        "SLOAD loop should find the recorded hash matching the symbolic key"
    );
    solver.pop(1);
}
