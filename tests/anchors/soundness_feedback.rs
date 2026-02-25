//! Anchor Test: shadow failure feedback can block a selector via lemma injection.

use alloy::primitives::Address;
use revm::primitives::Bytes;

#[test]
fn test_soundness_feedback_blocks_selector_after_false_positive() {
    dark_solver::solver::soundness::clear_false_positive_lemmas();

    let contract = Address::from([0x55; 20]);
    let call_data = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x00]);

    assert!(!dark_solver::solver::soundness::is_selector_blocked(
        contract, &call_data
    ));

    let lemma = dark_solver::solver::soundness::register_false_positive_selector(
        contract,
        &call_data,
        "shadow_fail step=0 selector=0xdeadbeef reason=Revert",
    )
    .expect("lemma must be generated");

    assert_eq!(lemma.selector, [0xde, 0xad, 0xbe, 0xef]);
    assert!(dark_solver::solver::soundness::is_selector_blocked(
        contract, &call_data
    ));
}
