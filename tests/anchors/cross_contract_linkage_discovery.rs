//! Anchor: bytecode-level call-target linkage discovery must only enqueue addresses that are
//! statically referenced near CALL-like opcodes.

use dark_solver::solver::heuristics::scan_for_call_targets;
use revm::primitives::{Address, Bytes};

fn push20(addr: Address) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x73); // PUSH20
    out.extend_from_slice(addr.as_slice());
    out
}

#[test]
fn test_scan_for_call_targets_detects_delegatecall_target() {
    let target = Address::new([0x11; 20]);
    let other = Address::new([0x22; 20]);

    // PUSH20 target; PUSH1 0; DELEGATECALL
    let mut code = Vec::new();
    code.extend_from_slice(&push20(target));
    code.push(0x60);
    code.push(0x00);
    code.push(0xf4); // DELEGATECALL

    // Noise: a different PUSH20 far away from call shouldn't be counted.
    code.extend_from_slice(&push20(other));
    code.extend(std::iter::repeat_n(0x00, 80));

    let bytecode = Bytes::from(code);
    let found = scan_for_call_targets(&bytecode, &[]);
    assert_eq!(found, vec![target]);
}

#[test]
fn test_scan_for_call_targets_respects_excludes() {
    let target = Address::new([0x33; 20]);
    let mut code = Vec::new();
    code.extend_from_slice(&push20(target));
    code.push(0xf1); // CALL

    let bytecode = Bytes::from(code);
    let found = scan_for_call_targets(&bytecode, &[target]);
    assert!(found.is_empty());
}
