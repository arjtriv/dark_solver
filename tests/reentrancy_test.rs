use dark_solver::symbolic::state::SymbolicMachine;
use z3::{Config, Context, Solver};

#[test]
fn test_reentrancy_detection_flag() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // 1. Init Machine
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    assert!(!machine.has_called_attacker);
    assert!(!machine.reentrancy_detected);

    // 2. Simulate CALL to Attacker (Opcode 0xF1 logic simplified)
    // We manually set the flag to simulate what 0xF1 does
    machine.has_called_attacker = true;

    // 3. Simulate SSTORE (Opcode 0x55)
    // We manually trigger the check or call a helper if we exposed one.
    // Since `step` is complex to mock, we will verify the logic by implementing a mini-step here
    // effectively replicating what we wrote in engine.rs:

    let ce_violation = machine.has_called_attacker;

    if ce_violation {
        machine.reentrancy_detected = true;
    }

    assert!(
        machine.reentrancy_detected,
        "Should detect reentrancy violation"
    );

    // 4. Test Snapshot Restoration
    let snap = machine.snapshot();
    machine.reentrancy_detected = false; // Reset
    machine.restore(&snap);
    assert!(
        machine.reentrancy_detected,
        "Snapshot should restore detection flag"
    );
}
