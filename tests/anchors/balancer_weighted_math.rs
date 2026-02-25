use dark_solver::protocols::balancer::{calc_in_given_out, calc_out_given_in};
use revm::primitives::U256;

#[test]
fn balancer_weighted_math_anchor() {
    let w80 = U256::from(800_000_000_000_000_000u128);
    let w20 = U256::from(200_000_000_000_000_000u128);
    let out = calc_out_given_in(
        U256::from(2_000_000u64),
        w80,
        U256::from(1_000_000u64),
        w20,
        U256::from(1_000u64),
        30,
    );
    assert!(out > U256::ZERO, "weighted swap output must be positive");

    let input_required = calc_in_given_out(
        U256::from(2_000_000u64),
        w80,
        U256::from(1_000_000u64),
        w20,
        U256::from(1_000u64),
        30,
    );
    assert!(
        input_required > U256::ZERO,
        "inverse quote must require non-zero input for non-zero output"
    );
}
