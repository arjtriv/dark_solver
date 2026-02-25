use dark_solver::symbolic::state::SymbolicMachine;
use z3::ast::Ast;
use z3::{ast::BV, Config, Context, Solver};

#[test]
fn test_snapshot_restore() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    // Initial State: x > 10
    let x = BV::new_const(&ctx, "x", 256);
    let ten = BV::from_u64(&ctx, 10, 256);

    solver.push();
    solver.assert(&x.bvugt(&ten));
    machine.solver_depth += 1;

    machine.call_handled = true;
    machine.total_branches = 7;
    machine.dead_end_pcs.insert(1337);

    // TAKE SNAPSHOT
    let snap = machine.snapshot();

    // Fork: x < 20
    solver.push(); // New Scope
    machine.solver_depth += 1;
    let twenty = BV::from_u64(&ctx, 20, 256);
    solver.assert(&x.bvult(&twenty));

    // Check SAT (11..19)
    assert_eq!(solver.check(), z3::SatResult::Sat);

    // Modifiy separate state (branch pushes)
    machine.branch_pushes += 1;
    machine.call_handled = false;
    machine.total_branches = 0;
    machine.dead_end_pcs.clear();

    // RESTORE
    machine.restore(&snap);

    // Logic Checks:
    // 1. Solver scopes should match snapshot
    assert_eq!(machine.solver_depth, snap.solver_scope_level);

    // 2. Branch pushes reset
    assert_eq!(machine.branch_pushes, snap.branch_pushes);

    // 2.5. Snapshot schema fields restore correctly
    assert!(machine.call_handled);
    assert_eq!(machine.total_branches, 7);
    assert!(machine.dead_end_pcs.contains(&1337));

    // 3. New constraints (x < 20) should be gone.
    // We only have x > 10.
    // Let's assert x == 100 is SAT (valid for x > 10, invalid for x < 20)
    solver.push();
    let hundred = BV::from_u64(&ctx, 100, 256);
    solver.assert(&x._eq(&hundred));
    assert_eq!(solver.check(), z3::SatResult::Sat);
    solver.pop(1);
}
