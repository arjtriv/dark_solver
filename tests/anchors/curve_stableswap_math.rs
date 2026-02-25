use dark_solver::protocols::curve::{
    compute_d_concrete, get_dy_concrete, get_virtual_price_concrete,
};
use revm::primitives::U256;

#[test]
fn curve_stableswap_math_anchor() {
    let x = U256::from(2_000_000u64);
    let y = U256::from(2_000_000u64);
    let a = U256::from(200u64);
    let d = compute_d_concrete(x, y, a);
    assert!(
        d > U256::ZERO,
        "Curve D must be non-zero for balanced liquidity"
    );

    let dy = get_dy_concrete(x, y, U256::from(10_000u64), a, 4);
    assert!(
        dy > U256::ZERO,
        "Curve get_dy must return executable output"
    );

    let vp = get_virtual_price_concrete(x, y, a, d);
    assert!(
        vp >= U256::from(900_000_000_000_000_000u128),
        "Curve virtual price should stay near 1e18 in balanced pools"
    );
}
