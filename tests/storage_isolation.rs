use alloy::primitives::{Address, U256};
use dark_solver::symbolic::state::SymbolicMachine;
use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};

#[test]
fn test_storage_isolation() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let addr_a = Address::from([0xaa; 20]);
    let addr_b = Address::from([0xbb; 20]);

    let key = U256::from(1);
    let val_a = U256::from(100);

    // 1. Write val_a to Key 1 in Contract A
    // Use manual hydration or simulate SSTORE context?
    // Let's use internal API for simplicity, mimicking SSTORE logic

    // Simulate Context A
    let storage_a_before = machine.get_storage(addr_a);
    let key_bv = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, key);
    let val_bv = dark_solver::symbolic::z3_ext::bv_from_u256(&ctx, val_a);
    let storage_a_after = storage_a_before.store(&key_bv, &val_bv);
    machine.storage.insert(addr_a, storage_a_after);

    // 2. Read Key 1 from Contract B (Should be 0)
    let storage_b = machine.get_storage(addr_b);
    let res = storage_b.select(&key_bv).as_bv().unwrap();

    // 3. Assert res == 0
    let zero = BV::from_u64(&ctx, 0, 256);
    solver.assert(&res._eq(&zero));

    assert_eq!(
        solver.check(),
        z3::SatResult::Sat,
        "Contract B should have empty storage at key 1"
    );

    // 4. Assert Contract A has value
    let storage_a_read = machine.get_storage(addr_a).select(&key_bv).as_bv().unwrap();
    solver.assert(&storage_a_read._eq(&val_bv));
    assert_eq!(
        solver.check(),
        z3::SatResult::Sat,
        "Contract A should have value 100 at key 1"
    );
}
