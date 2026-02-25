use std::fs;

use dark_solver::solver::heuristics::scan_dead_end_pcs;
use revm::primitives::Bytes;

#[test]
fn test_fast_path_revert_injection_marks_depth0_guaranteed_revert() {
    let bytecode = Bytes::from(vec![
        0x60, 0x00, // PUSH1 0
        0x60, 0x00, // PUSH1 0
        0xfd, // REVERT
    ]);
    let dead_ends = scan_dead_end_pcs(&bytecode);
    assert!(
        dead_ends.contains(&0),
        "depth-0 unconditional REVERT must be injected into dead_end_pcs at PC=0"
    );
}

#[test]
fn test_fast_path_revert_injection_is_checked_before_opcode_dispatch() {
    let engine_source = fs::read_to_string("src/symbolic/engine.rs")
        .expect("src/symbolic/engine.rs must be readable for fast-path revert anchor");
    assert!(
        engine_source.contains("if self.dead_end_pcs.contains(&pc)"),
        "symbolic engine must early-abort when pc is pre-marked as dead end"
    );
}
