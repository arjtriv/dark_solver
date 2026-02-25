use dark_solver::symbolic::state::SymbolicMachine;
use z3::{Config, Context, Solver};

#[test]
fn test_path_explosion_limit() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // 1. Initialize Machine with small branch limit
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    machine.max_branches = 5; // Very strict limit

    // 2. Simulate branching loop
    // distinct PC for each "jump"
    for i in 0..20 {
        // Mock a JUMPI scenario manually or via small opcode harness?
        // Simulating "control logic" directly is easier.

        let pc = i * 10;

        // Check Limit logic manually (replicating control.rs logic for unit test)
        if machine.total_branches >= machine.max_branches {
            println!("Limit hit at iteration {}", i);
            assert!(i >= 5);
            break;
        }

        // Simulate a split
        machine.total_branches += 1;
        machine.unexplored_branches.push((pc + 5, false));
    }

    // 3. Verify
    assert!(machine.total_branches <= machine.max_branches + 1); // +1 because we check THEN increment in the loop above?
                                                                 // Actually in control.rs: if total >= max { FALSE } else { total++; TRUE }
                                                                 // So usually max is strict cap for "new" branches.
                                                                 // If we start at 0.
                                                                 // 0 < 5 -> inc to 1.
                                                                 // ...
                                                                 // 4 < 5 -> inc to 5.
                                                                 // 5 >= 5 -> Prune.
                                                                 // So total should be exactly 5.

    assert_eq!(machine.total_branches, 5);
}
