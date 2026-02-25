//! Anchor Test: Dead End Branch Pruning
//!
//! Proves that the dead-end scanner correctly identifies 
//! JUMPDEST → REVERT patterns as dead-end PCs.

use revm::primitives::Bytes;
use dark_solver::solver::heuristics::scan_dead_end_pcs;

#[test]
fn test_identifies_jumpdest_revert_pattern() {
    // JUMPDEST (0x5B) immediately followed by REVERT (0xFD)
    // This is the most basic dead-end pattern.
    let bytecode = Bytes::from(vec![
        0x60, 0x00,       // PUSH1 0
        0x56,             // JUMP 
        0x5B, 0xFD,       // JUMPDEST → REVERT (dead end at PC 3)
        0x00,             // STOP
    ]);

    let dead_ends = scan_dead_end_pcs(&bytecode);
    assert!(
        dead_ends.contains(&3),
        "JUMPDEST at PC 3 followed by REVERT should be detected as dead end. Got: {:?}",
        dead_ends
    );
}

#[test]
fn test_identifies_jumpdest_invalid_pattern() {
    // JUMPDEST (0x5B) followed by INVALID (0xFE) — Solidity assert/panic handler
    let bytecode = Bytes::from(vec![
        0x5B, 0xFE,  // JUMPDEST → INVALID (dead end at PC 0)
    ]);

    let dead_ends = scan_dead_end_pcs(&bytecode);
    assert!(
        dead_ends.contains(&0),
        "JUMPDEST at PC 0 followed by INVALID should be detected. Got: {:?}",
        dead_ends
    );
}

#[test]
fn test_ignores_jumpdest_with_sstore() {
    // JUMPDEST followed by SSTORE — NOT a dead end (state-changing op)
    let bytecode = Bytes::from(vec![
        0x5B, 0x55, 0xFD,  // JUMPDEST → SSTORE → REVERT
    ]);

    let dead_ends = scan_dead_end_pcs(&bytecode);
    // Should NOT be in dead_ends because SSTORE is a state-changing op
    assert!(
        !dead_ends.contains(&0),
        "JUMPDEST followed by SSTORE should NOT be a dead end. Got: {:?}",
        dead_ends
    );
}

#[test]
fn test_error_selector_revert_pattern() {
    // Solidity custom error: JUMPDEST → PUSH4 selector → PUSH1 0 → MSTORE → ... → REVERT
    // JUMPDEST PUSH4 xx xx xx xx PUSH1 00 REVERT
    let bytecode = Bytes::from(vec![
        0x00,                         // STOP (padding)
        0x5B,                         // JUMPDEST at PC 1
        0x63, 0xAA, 0xBB, 0xCC, 0xDD, // PUSH4 0xAABBCCDD (error selector)
        0x60, 0x00,                    // PUSH1 0
        0x52,                         // MSTORE
        0xFD,                         // REVERT at PC 10
    ]);

    let dead_ends = scan_dead_end_pcs(&bytecode);
    assert!(
        dead_ends.contains(&1),
        "JUMPDEST at PC 1 with error selector → REVERT within 12 bytes should be dead end. Got: {:?}",
        dead_ends
    );
}

#[test]
fn test_empty_bytecode() {
    let bytecode = Bytes::new();
    let dead_ends = scan_dead_end_pcs(&bytecode);
    assert!(dead_ends.is_empty(), "Empty bytecode should have no dead ends");
}
