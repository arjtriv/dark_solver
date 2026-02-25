#[cfg(test)]
mod tests {
    use dark_solver::symbolic::oracle::StorageSlotInfo;
    use dark_solver::symbolic::state::SymbolicMachine;
    use revm::primitives::{keccak256, Address, U256};
    use z3::ast::{Ast, BV};
    use z3::{Config, Context, Solver};

    #[test]
    fn test_keccak_preimage_recovery() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        // Note: fork_url None is okay for this unit test as we mock DB interactions manually if needed,
        // but here we test the Solver/State Logic primarily.
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // 1. Setup Oracle with a known "Common Slot"
        // Let's pretend we are accessing `mapping(address => uint) balances` at slot 0.
        // Attacker address: 0x12..34
        let attacker = Address::from([0x12; 20]);
        let slot_num = U256::ZERO;

        let mut input = vec![0u8; 12];
        input.extend_from_slice(attacker.as_slice());
        input.extend_from_slice(&slot_num.to_be_bytes::<32>());

        let target_hash = keccak256(&input);
        let target_hash_u256 = U256::from_be_bytes(target_hash.0);

        // Pre-seed Oracle (manually for test to ensure control)
        machine.oracle.common_slots.insert(
            target_hash_u256,
            StorageSlotInfo {
                description: "balances[attacker]".to_string(),
                base_slot: 0,
                inputs: vec![input.clone()],
            },
        );

        // Hydrate Preimage Map (normally done in seed_oracle)
        // We need to do this so state.rs record_sha3 sees it!
        // We simulate the logic of `seed_oracle` here correctly for the test.
        let mut chunks = Vec::new();
        // The input 'input' is 32 bytes (12 pad + 20 addr) + 32 bytes (slot) = 64 bytes.
        // Or is it?
        // `input` starts with 12 bytes 0x00. Then 20 bytes 0x12...
        // Then append 32 bytes of slot.
        // Total 64 bytes.
        for chunk in input.chunks(32) {
            let mut padded = [0u8; 32];
            let len = chunk.len().min(32);
            padded[..len].copy_from_slice(&chunk[..len]);
            chunks.push(dark_solver::symbolic::z3_ext::bv_from_u256(
                machine.context,
                U256::from_be_bytes(padded),
            ));
        }
        machine
            .oracle
            .preimage_map
            .insert(target_hash_u256, chunks.clone());

        // 2. Create Symbolic Key
        // key = Symbolic Address Value (as a U256/BV)
        // In EVM memory, the key is padded to 32 bytes.
        let key_bv = BV::new_const(&ctx, "sym_key", 256);

        // Trace: [key_bv, slot_bv]
        // This closely mimics `mapping(key => x)` pattern in Memory.
        let slot_bv = dark_solver::symbolic::z3_ext::bv_from_u256(machine.context, U256::ZERO);

        // To properly test "Partial Quantification", we need `record_sha3` to be called.
        // And `record_sha3` is called when SHA3 opcode runs.
        let sym_hash = BV::new_const(&ctx, "sym_hash", 256);

        let trace = dark_solver::symbolic::patterns::SHA3Trace {
            preimage: vec![key_bv.clone(), slot_bv.clone()],
            hash: sym_hash.clone(),
            size: BV::from_u64(&ctx, 64, 256), // 64 bytes
            pc: 0,
        };

        println!("Recording SHA3 trace...");
        machine.record_sha3(trace);

        // 3. Constrain Equality
        // Assert: sym_hash == target_hash
        // This simulates the Memory Opcode (0x54) creating a branch where `slot == candidate`.
        let target_hash_bv =
            dark_solver::symbolic::z3_ext::bv_from_u256(machine.context, target_hash_u256);
        solver.assert(&sym_hash._eq(&target_hash_bv));

        // 4. Verify Implication
        // If "Partial Quantification" works, then:
        // sym_hash == target_hash => inputs == inputs
        // Specifically: key_bv == attacker_address (padded)

        let expected_key_val = U256::from_be_bytes({
            let mut arr = [0u8; 32];
            arr[12..].copy_from_slice(attacker.as_slice());
            arr
        });
        let expected_key_bv =
            dark_solver::symbolic::z3_ext::bv_from_u256(machine.context, expected_key_val);

        // Check UNSAT if key != expected
        solver.push();
        solver.assert(&key_bv._eq(&expected_key_bv).not());

        let res = solver.check();
        println!("Solver Result (should be Unsat): {:?}", res);
        assert_eq!(
            res,
            z3::SatResult::Unsat,
            "Solver should prove key matches attacker due to injectivity"
        );
        solver.pop(1);

        // Success!
    }
}
