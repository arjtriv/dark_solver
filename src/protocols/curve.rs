use crate::symbolic::utils::math::{extend_to_512, val};
use alloy::primitives::U256;
use std::sync::atomic::{AtomicU64, Ordering};
use z3::ast::{Ast, Bool, BV};

static CURVE_SYMBOLIC_NONCE: AtomicU64 = AtomicU64::new(0);

/// Symbolic Curve StableSwap Invariant Check (n=2)
///
/// StableSwap Invariant:
/// 4A(x+y) + D = 4AD + D^3/(4xy)
///
/// Rearranged to avoid division (multiply by 4xy):
/// 16Axy(x+y) + 4xyD = 16ADxy + D^3
///
/// All calculations use 512-bit arithmetic to prevent overflow.
///
/// Returns a boolean constraint that is true if the invariant holds.
/// This allows the solver to find valid (x, y) pairs that satisfy the curve.
pub fn is_invariant_satisfied<'ctx>(
    ctx: &'ctx z3::Context,
    x: &BV<'ctx>,
    y: &BV<'ctx>,
    amp: &BV<'ctx>, // Amplification coefficient A
    d: &BV<'ctx>,   // Invariant D
) -> z3::ast::Bool<'ctx> {
    // Extend all inputs to 512-bit
    let x_512 = extend_to_512(ctx, x);
    let y_512 = extend_to_512(ctx, y);
    let a_512 = extend_to_512(ctx, amp);
    let d_512 = extend_to_512(ctx, d);

    let n4 = extend_to_512(ctx, &val(ctx, 4));
    let n16 = extend_to_512(ctx, &val(ctx, 16));

    // Term 1: 16 * A * x * y * (x + y)
    let xy = x_512.bvmul(&y_512);
    let x_plus_y = x_512.bvadd(&y_512);
    let term1 = n16.bvmul(&a_512).bvmul(&xy).bvmul(&x_plus_y);

    // Term 2: 4 * x * y * D
    let term2 = n4.bvmul(&xy).bvmul(&d_512);

    // LHS = Term 1 + Term 2
    let lhs = term1.bvadd(&term2);

    // Term 3: 16 * A * D * x * y
    let term3 = n16.bvmul(&a_512).bvmul(&d_512).bvmul(&xy);

    // Term 4: D^3
    let d_squared = d_512.bvmul(&d_512);
    let d_cubed = d_squared.bvmul(&d_512);

    // RHS = Term 3 + Term 4
    let rhs = term3.bvadd(&d_cubed);

    // Check equality
    lhs._eq(&rhs)
}

fn checked_mul(a: U256, b: U256) -> Option<U256> {
    a.checked_mul(b)
}

fn checked_add(a: U256, b: U256) -> Option<U256> {
    a.checked_add(b)
}

fn checked_sub(a: U256, b: U256) -> Option<U256> {
    a.checked_sub(b)
}

/// Newton's method for Curve n=2 pools, using the same iterative shape as Vyper pools.
///
/// Returns `0` on invalid/degenerate inputs or arithmetic overflow.
pub fn compute_d_concrete(x: U256, y: U256, a: U256) -> U256 {
    if x.is_zero() || y.is_zero() || a.is_zero() {
        return U256::ZERO;
    }

    let n = U256::from(2u64);
    let ann = match checked_mul(a, U256::from(4u64)) {
        Some(v) if !v.is_zero() => v,
        _ => return U256::ZERO,
    };

    let s = match checked_add(x, y) {
        Some(v) if !v.is_zero() => v,
        _ => return U256::ZERO,
    };
    let mut d = s;

    for _ in 0..255 {
        let d_prev = d;

        let denom_x = match checked_mul(x, n) {
            Some(v) if !v.is_zero() => v,
            _ => return U256::ZERO,
        };
        let denom_y = match checked_mul(y, n) {
            Some(v) if !v.is_zero() => v,
            _ => return U256::ZERO,
        };

        let mut d_p = d;
        d_p = match checked_mul(d_p, d) {
            Some(v) => v / denom_x,
            None => return U256::ZERO,
        };
        d_p = match checked_mul(d_p, d) {
            Some(v) => v / denom_y,
            None => return U256::ZERO,
        };

        let ann_s = match checked_mul(ann, s) {
            Some(v) => v,
            None => return U256::ZERO,
        };
        let two_d_p = match checked_mul(d_p, n) {
            Some(v) => v,
            None => return U256::ZERO,
        };
        let numerator = match checked_mul(
            d,
            match checked_add(ann_s, two_d_p) {
                Some(v) => v,
                None => return U256::ZERO,
            },
        ) {
            Some(v) => v,
            None => return U256::ZERO,
        };

        let ann_minus_one = match checked_sub(ann, U256::from(1u64)) {
            Some(v) => v,
            None => return U256::ZERO,
        };
        let left = match checked_mul(ann_minus_one, d) {
            Some(v) => v,
            None => return U256::ZERO,
        };
        let right = match checked_mul(d_p, U256::from(3u64)) {
            Some(v) => v,
            None => return U256::ZERO,
        };
        let denominator = match checked_add(left, right) {
            Some(v) if !v.is_zero() => v,
            _ => return U256::ZERO,
        };

        d = numerator / denominator;
        if d == d_prev || d.abs_diff(d_prev) <= U256::from(1u64) {
            return d;
        }
    }

    d
}

fn compute_y_concrete(x_new: U256, d: U256, a: U256) -> U256 {
    if x_new.is_zero() || d.is_zero() || a.is_zero() {
        return U256::ZERO;
    }

    let n = U256::from(2u64);
    let ann = match checked_mul(a, U256::from(4u64)) {
        Some(v) if !v.is_zero() => v,
        _ => return U256::ZERO,
    };

    let denom_x = match checked_mul(x_new, n) {
        Some(v) if !v.is_zero() => v,
        _ => return U256::ZERO,
    };
    let ann_n = match checked_mul(ann, n) {
        Some(v) if !v.is_zero() => v,
        _ => return U256::ZERO,
    };

    // c = D^3 / (x_new * n * Ann * n)
    let mut c = d;
    c = match checked_mul(c, d) {
        Some(v) => v / denom_x,
        None => return U256::ZERO,
    };
    c = match checked_mul(c, d) {
        Some(v) => v / ann_n,
        None => return U256::ZERO,
    };

    let b = match checked_add(x_new, d / ann) {
        Some(v) => v,
        None => return U256::ZERO,
    };

    let mut y = d;
    for _ in 0..255 {
        let y_prev = y;
        let numerator = match checked_add(
            match checked_mul(y, y) {
                Some(v) => v,
                None => return U256::ZERO,
            },
            c,
        ) {
            Some(v) => v,
            None => return U256::ZERO,
        };
        let denominator = match checked_add(
            match checked_mul(y, U256::from(2u64)) {
                Some(v) => v,
                None => return U256::ZERO,
            },
            b,
        )
        .and_then(|v| checked_sub(v, d))
        {
            Some(v) if !v.is_zero() => v,
            _ => return U256::ZERO,
        };
        y = numerator / denominator;

        if y == y_prev || y.abs_diff(y_prev) <= U256::from(1u64) {
            return y;
        }
    }

    y
}

/// Concrete swap quote for Curve n=2 pools.
///
/// `fee_bps` is applied on output amount with a 10_000 denominator.
pub fn get_dy_concrete(x_balance: U256, y_balance: U256, dx: U256, a: U256, fee_bps: u64) -> U256 {
    if x_balance.is_zero() || y_balance.is_zero() || dx.is_zero() || a.is_zero() {
        return U256::ZERO;
    }

    let d = compute_d_concrete(x_balance, y_balance, a);
    if d.is_zero() {
        return U256::ZERO;
    }

    let x_new = match checked_add(x_balance, dx) {
        Some(v) => v,
        None => return U256::ZERO,
    };
    let y_new = compute_y_concrete(x_new, d, a);
    if y_new >= y_balance {
        return U256::ZERO;
    }

    let one = U256::from(1u64);
    let raw_dy = if y_balance > y_new.saturating_add(one) {
        y_balance - y_new - one
    } else {
        U256::ZERO
    };
    if raw_dy.is_zero() {
        return U256::ZERO;
    }

    let fee = match checked_mul(raw_dy, U256::from(fee_bps)) {
        Some(v) => v / U256::from(10_000u64),
        None => return U256::ZERO,
    };
    raw_dy.saturating_sub(fee)
}

/// Symbolic n=2 Curve output model.
///
/// Returns `(dy, constraints)` where `constraints` must be asserted by the caller.
pub fn get_dy_symbolic<'ctx>(
    ctx: &'ctx z3::Context,
    x: &BV<'ctx>,
    y: &BV<'ctx>,
    dx: &BV<'ctx>,
    amp: &BV<'ctx>,
    d: &BV<'ctx>,
) -> (BV<'ctx>, Bool<'ctx>) {
    let nonce = CURVE_SYMBOLIC_NONCE.fetch_add(1, Ordering::Relaxed);
    let y_after_name = format!("curve_y_after_{}", nonce);
    let y_after = BV::new_const(ctx, y_after_name.as_str(), 256);
    let x_after = x.bvadd(dx);
    let zero = val(ctx, 0);

    let y_monotone = y.bvuge(&y_after);
    let dy = y_monotone.ite(&y.bvsub(&y_after), &zero);
    let amp_positive = amp.bvugt(&zero);
    let y_positive = y_after.bvugt(&zero);
    let dx_zero = dx._eq(&zero);
    let dy_zero = dy._eq(&zero);
    let dy_positive = dy.bvugt(&zero);

    let invariant = is_invariant_satisfied(ctx, &x_after, &y_after, amp, d);
    let constraints = Bool::and(
        ctx,
        &[
            &amp_positive,
            &y_monotone,
            &y_positive,
            &invariant,
            &dx_zero.implies(&dy_zero),
            &dx_zero.not().implies(&dy_positive),
        ],
    );
    (dy, constraints)
}

/// LP virtual price, scaled by 1e18.
pub fn get_virtual_price_concrete(x: U256, y: U256, a: U256, total_supply: U256) -> U256 {
    if total_supply.is_zero() {
        return U256::ZERO;
    }
    let d = compute_d_concrete(x, y, a);
    if d.is_zero() {
        return U256::ZERO;
    }
    match checked_mul(d, U256::from(1_000_000_000_000_000_000u128)) {
        Some(v) => v / total_supply,
        None => U256::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compute_d_concrete, get_dy_concrete, get_dy_symbolic, get_virtual_price_concrete,
        is_invariant_satisfied,
    };
    use alloy::primitives::U256;
    use z3::ast::BV;
    use z3::{Config, Context};

    #[test]
    fn compute_d_concrete_returns_zero_on_degenerate_inputs() {
        assert_eq!(
            compute_d_concrete(U256::ZERO, U256::from(10u64), U256::from(100u64)),
            U256::ZERO
        );
        assert_eq!(
            compute_d_concrete(U256::from(10u64), U256::ZERO, U256::from(100u64)),
            U256::ZERO
        );
    }

    #[test]
    fn compute_d_concrete_is_non_zero_for_balanced_pool() {
        let x = U256::from(1_000_000u64);
        let y = U256::from(1_000_000u64);
        let a = U256::from(100u64);
        let d = compute_d_concrete(x, y, a);
        assert!(d > U256::ZERO);
    }

    #[test]
    fn compute_d_concrete_is_symmetric_in_x_y() {
        let x = U256::from(1_250_000u64);
        let y = U256::from(975_000u64);
        let a = U256::from(200u64);
        let d_xy = compute_d_concrete(x, y, a);
        let d_yx = compute_d_concrete(y, x, a);
        assert_eq!(d_xy, d_yx);
    }

    #[test]
    fn get_dy_concrete_returns_positive_output() {
        let x = U256::from(1_500_000u64);
        let y = U256::from(1_500_000u64);
        let dx = U256::from(10_000u64);
        let a = U256::from(200u64);
        let dy = get_dy_concrete(x, y, dx, a, 4);
        assert!(dy > U256::ZERO);
        assert!(dy < y);
    }

    #[test]
    fn get_dy_concrete_respects_fee() {
        let x = U256::from(1_500_000u64);
        let y = U256::from(1_500_000u64);
        let dx = U256::from(10_000u64);
        let a = U256::from(200u64);
        let dy_no_fee = get_dy_concrete(x, y, dx, a, 0);
        let dy_with_fee = get_dy_concrete(x, y, dx, a, 30);
        assert!(dy_no_fee >= dy_with_fee);
    }

    #[test]
    fn get_virtual_price_concrete_returns_q18_scaled_value() {
        let x = U256::from(2_000_000u64);
        let y = U256::from(2_000_000u64);
        let a = U256::from(200u64);
        let d = compute_d_concrete(x, y, a);
        let vp = get_virtual_price_concrete(x, y, a, d);
        assert_eq!(vp, U256::from(1_000_000_000_000_000_000u128));
    }

    #[test]
    fn get_dy_symbolic_builds_256bit_output() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let x = BV::from_u64(&ctx, 1_000_000, 256);
        let y = BV::from_u64(&ctx, 1_000_000, 256);
        let dx = BV::from_u64(&ctx, 1_000, 256);
        let amp = BV::from_u64(&ctx, 200, 256);
        let d = BV::from_u64(&ctx, 2_000_000, 256);

        let (dy, constraints) = get_dy_symbolic(&ctx, &x, &y, &dx, &amp, &d);
        assert_eq!(dy.get_size(), 256);
        let _ = constraints;
        // Keep this test structural: nonlinear solving here can be expensive on CI.
        let _ = is_invariant_satisfied(&ctx, &x.bvadd(&dx), &y, &amp, &d);
    }
}
