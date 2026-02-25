use dark_solver::solver::heuristics::{scan_for_call_targets, scan_for_call_targets_bytes};
use revm::primitives::{Address, Bytes};

#[test]
fn test_scan_for_call_targets_bytes_matches_bytes_wrapper() {
    let target = Address::from_slice(&[0x11u8; 20]);
    let mut bytecode = Vec::new();
    bytecode.push(0x73); // PUSH20
    bytecode.extend_from_slice(target.as_slice());
    bytecode.push(0x5b); // JUMPDEST
    bytecode.push(0xf1); // CALL
    let bytes = Bytes::from(bytecode.clone());

    let a = scan_for_call_targets(&bytes, &[]);
    let b = scan_for_call_targets_bytes(&bytecode, &[]);
    assert_eq!(a, b);
    assert_eq!(a, vec![target]);
}

#[test]
fn test_scan_for_call_targets_bytes_respects_exclusion_and_dedup() {
    let target = Address::from_slice(&[0x22u8; 20]);
    let mut bytecode = Vec::new();
    // Two nearby CALL-like opcodes should still produce one deduped target.
    bytecode.push(0x73);
    bytecode.extend_from_slice(target.as_slice());
    bytecode.push(0xf1); // CALL
    bytecode.push(0xf4); // DELEGATECALL

    let excluded = scan_for_call_targets_bytes(&bytecode, &[target]);
    assert!(excluded.is_empty());

    let included = scan_for_call_targets_bytes(&bytecode, &[]);
    assert_eq!(included, vec![target]);
}
