use dark_solver::solver::setup::compute_zero_state_flag;
use revm::primitives::{Bytes, U256};

#[test]
fn test_compute_zero_state_flag_is_strict() {
    let empty_code = Bytes::from_static(&[]);
    let nonempty_code = Bytes::from_static(&[0x60, 0x00]);

    let empty_storage: Vec<(U256, U256)> = Vec::new();
    let nonempty_storage: Vec<(U256, U256)> = vec![(U256::from(1u64), U256::from(2u64))];

    assert!(
        compute_zero_state_flag(&empty_code, Some(U256::ZERO), &empty_storage, true),
        "empty code + zero balance + empty storage (scan ok) must be ZERO_STATE"
    );

    assert!(
        !compute_zero_state_flag(&nonempty_code, Some(U256::ZERO), &empty_storage, true),
        "non-empty bytecode must never be classified as ZERO_STATE"
    );

    assert!(
        !compute_zero_state_flag(&empty_code, Some(U256::from(1u64)), &empty_storage, true),
        "non-zero balance must never be classified as ZERO_STATE"
    );

    assert!(
        !compute_zero_state_flag(&empty_code, Some(U256::ZERO), &nonempty_storage, true),
        "non-empty storage must never be classified as ZERO_STATE"
    );

    assert!(
        !compute_zero_state_flag(&empty_code, Some(U256::ZERO), &empty_storage, false),
        "storage scan failure must fail closed (not ZERO_STATE)"
    );

    assert!(
        !compute_zero_state_flag(&empty_code, None, &empty_storage, true),
        "unknown balance must fail closed (not ZERO_STATE)"
    );
}
