#[cfg(test)]
mod tests {
    use dark_solver::symbolic::state::SymbolicMachine;
    use revm::primitives::{Address, U256};
    use z3::ast::{Ast, BV};
    use z3::{Config, Context, Solver};

    #[test]
    fn test_uninitialized_storage_should_be_zero() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // 1. Hydrate with slot 0 = 100
        machine.hydrate_storage(Address::ZERO, vec![(U256::from(0), U256::from(100))]);

        // 2. Read from UNHYDRATED slot 999 (never written on-chain, should be 0)
        let uninitialized_slot = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, U256::from(999));
        let value = machine
            .get_storage(Address::ZERO)
            .select(&uninitialized_slot)
            .as_bv()
            .unwrap();

        // 3. Soundness check: can Z3 find a solution where value != 0?
        solver.push();
        solver.assert(&value.bvugt(&BV::from_u64(&ctx, 0, 256)));
        let result = solver.check();
        solver.pop(1);

        // EXPECTED: Unsat (uninitialized storage must be 0)
        // ACTUAL: Sat (Z3 can assign any value to uninitialized slots)
        if result == z3::SatResult::Sat {
            println!("❌ BUG CONFIRMED: Uninitialized storage can have non-zero value!");
            println!("This causes false negatives - missing exploits that check for zero values.");

            if let Some(model) = solver.get_model() {
                if let Some(val) = model.eval(&value, true) {
                    println!("Z3 assigned value: {:?}", val);
                }
            }
            panic!("SOUNDNESS BUG: Uninitialized storage is not constrained to 0");
        } else {
            println!("✅ PASS: Uninitialized storage correctly defaults to 0");
        }
    }

    #[test]
    fn test_symbolic_slot_with_unhydrated_value() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // Hydrate with one known slot
        let known_hash = U256::from(12345);
        machine.hydrate_storage(Address::ZERO, vec![(known_hash, U256::from(999))]);

        // Create symbolic slot and constrain it to an UNKNOWN hash
        let sym_slot = BV::new_const(&ctx, "sym_slot", 256);
        let unknown_hash = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, U256::from(67890)); // Not in hydrated slots

        solver.assert(&sym_slot._eq(&unknown_hash));

        // Read from storage
        let value = machine
            .get_storage(Address::ZERO)
            .select(&sym_slot)
            .as_bv()
            .unwrap();

        // What value does Z3 return for this unhydrated slot?
        solver.push();
        solver.assert(&value._eq(&dark_solver::symbolic::z3_ext::bv_from_u256(
            &ctx,
            U256::from(0),
        )));
        let is_zero = solver.check();
        solver.pop(1);

        solver.push();
        solver.assert(&value.bvugt(&BV::from_u64(&ctx, 0, 256)));
        let is_nonzero = solver.check();
        solver.pop(1);

        println!("Unhydrated slot can be zero: {:?}", is_zero);
        println!("Unhydrated slot can be non-zero: {:?}", is_nonzero);

        if is_nonzero == z3::SatResult::Sat {
            panic!("SOUNDNESS BUG: Unhydrated slots should default to 0, but Z3 allows non-zero values");
        }
    }

    #[test]
    fn test_concrete_slot_lookup_performance() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // Hydrate many slots to simulate realistic contract
        let mut slots = Vec::new();
        for i in 0..1000 {
            slots.push((U256::from(i), U256::from(i * 10)));
        }
        machine.hydrate_storage(Address::ZERO, slots);

        // Time concrete lookup
        let start = std::time::Instant::now();
        for i in 0..100 {
            let slot = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, U256::from(i));
            let _value = machine
                .get_storage(Address::ZERO)
                .select(&slot)
                .as_bv()
                .unwrap();
        }
        let elapsed = start.elapsed();

        println!(
            "100 concrete SLOADs with 1000 hydrated slots: {:?}",
            elapsed
        );

        // This should be fast (<10ms), but without optimization it might be slow
        if elapsed.as_millis() > 100 {
            println!(
                "⚠️  WARNING: Concrete SLOAD is slow ({:?}ms). Consider adding fast path.",
                elapsed.as_millis()
            );
        }
    }
}
