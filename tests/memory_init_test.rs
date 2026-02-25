use dark_solver::symbolic::state::SymbolicMachine;
use z3::ast::Ast;
use z3::{ast::BV, Config, Context, Solver};

#[test]
fn test_uninitialized_memory_is_zero() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // 1. Byte Read Test
    // Pick an arbitrary address (e.g., 0x1234)
    let addr = BV::from_u64(&ctx, 0x1234, 256);

    // Read byte
    let byte = machine.read_byte(addr);

    // Assert it is concretely 0
    // machine.memory is const_array(0), so select(any) should be 0.
    let zero = BV::from_u64(&ctx, 0, 8);

    // Check with solver: "Is it possible for byte != 0?"
    solver.push();
    solver.assert(&byte._eq(&zero).not());
    let result = solver.check();
    assert_eq!(
        result,
        z3::SatResult::Unsat,
        "Uninitialized memory byte MUST be zero"
    );
    solver.pop(1);

    // 2. Word Read Test (MLOAD uses this)
    let addr_word = BV::from_u64(&ctx, 0x2000, 256);
    let word = machine.read_word(addr_word);
    let zero_word = BV::from_u64(&ctx, 0, 256);

    solver.push();
    solver.assert(&word._eq(&zero_word).not());
    let result_word = solver.check();
    assert_eq!(
        result_word,
        z3::SatResult::Unsat,
        "Uninitialized word MUST be zero"
    );
    solver.pop(1);

    // 3. Write and Read Back (Sanity Check that it's not ALWAYS zero regardless of writes)
    let write_addr = BV::from_u64(&ctx, 0x3000, 256);
    let val = BV::from_u64(&ctx, 0xFF, 8);
    machine.write_byte(write_addr.clone(), val.clone());

    let read_back = machine.read_byte(write_addr);
    solver.push();
    solver.assert(&read_back._eq(&val).not());
    let result_read_back = solver.check();
    assert_eq!(
        result_read_back,
        z3::SatResult::Unsat,
        "Written value should be retrievable"
    );
    solver.pop(1);
}
