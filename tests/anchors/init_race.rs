//! Anchor Test: initialization race selector/payload model remains stable.

use alloy::primitives::{keccak256, Address};
use revm::primitives::Bytes;

#[test]
fn test_init_race_selector_and_payload_anchor() {
    let hash = keccak256("initialize()".as_bytes());
    let initialize_selector = [hash[0], hash[1], hash[2], hash[3]];
    assert!(dark_solver::protocols::init_race::is_initialization_selector(initialize_selector));

    let attacker = Address::from([0x42; 20]);
    let payloads = dark_solver::protocols::init_race::build_initializer_payloads(
        initialize_selector,
        attacker,
    );
    assert_eq!(payloads.len(), 3);
    assert_eq!(&payloads[0][..4], initialize_selector.as_slice());
    assert_eq!(&payloads[1][16..36], attacker.as_slice());

    let extracted = dark_solver::protocols::init_race::selector_from_call_data(
        &Bytes::copy_from_slice(&payloads[2]),
    );
    assert_eq!(extracted, Some(initialize_selector));
}
