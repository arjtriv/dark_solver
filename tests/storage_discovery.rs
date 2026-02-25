#[cfg(test)]
mod tests {
    use dark_solver::symbolic::state::SymbolicMachine;
    use revm::primitives::{keccak256, Address, U256};
    use z3::ast::{Ast, BV};
    use z3::{Config, Context, Solver};

    // We can't easily mock ForkDB's RPC calls here without setting up a full server.
    // Instead, we will simulate the "Hydration" and "SLOAD" part to verify the logic.
    // The RPC scanning part is trusted to work if the RPC is compliant (debug_storageRangeAt).

    #[test]
    fn test_storage_discovery_logic() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // 1. Simulate "Scan Storage" Result
        // Assume we found a "Secret Slot" at key `keccak("secret")` with value 999.
        let secret = b"secret";
        let secret_hash = keccak256(secret);
        let secret_hash_u256 = U256::from_be_bytes(secret_hash.0);
        let secret_val = U256::from(999);

        let scanned_slots = vec![(secret_hash_u256, secret_val)];

        // 2. Hydrate Storage
        machine.hydrate_storage(Address::ZERO, scanned_slots);

        // 3. Symbolic Access
        // We do SLOAD(sym_slot).
        // Constraint: sym_slot == secret_hash.
        // Expect: Result == 999.

        let sym_slot = BV::new_const(&ctx, "sym_slot", 256);

        // This simulates `memory.rs` simplified SLOAD
        let res = machine
            .get_storage(Address::ZERO)
            .select(&sym_slot)
            .as_bv()
            .unwrap();

        // 4. Solve
        // Assert: res == 999
        let expected_val_bv = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, secret_val);

        solver.push();
        solver.assert(&res._eq(&expected_val_bv));

        // Can we find a sym_slot that satisfies this?
        // It should be `secret_hash`.
        let check_res = solver.check();
        assert_eq!(
            check_res,
            z3::SatResult::Sat,
            "Should find slot with value 999"
        );

        let model = solver.get_model().unwrap();
        let solved_slot = model.eval(&sym_slot, true).unwrap();
        let solved_slot_u256 = dark_solver::symbolic::z3_ext::u256_from_bv(&solved_slot)
            .expect("solver must produce concrete slot");
        assert_eq!(
            solved_slot_u256, secret_hash_u256,
            "Solved slot should be the secret hash"
        );
        solver.pop(1);
    }
}
