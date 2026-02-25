use alloy::primitives::U256;
use std::str::FromStr;
use z3::ast::{Ast, Bool, BV};

const WEIGHT_SCALE: u128 = 1_000_000_000_000_000_000u128;
const FEE_DENOMINATOR_BPS: u64 = 10_000;
const POW_GUARD_MIN: f64 = 1e-18;

fn u256_to_f64(v: U256) -> Option<f64> {
    v.to_string().parse::<f64>().ok()
}

fn f64_floor_to_u256(v: f64) -> Option<U256> {
    if !v.is_finite() || v < 0.0 {
        return None;
    }
    // Balancer math is floor-biased for output and ceil-biased for input.
    let floored = v.floor();
    U256::from_str(&format!("{:.0}", floored)).ok()
}

fn fee_adjusted_amount_in(amount_in: U256, swap_fee_bps: u64) -> Option<U256> {
    if swap_fee_bps >= FEE_DENOMINATOR_BPS {
        return None;
    }
    amount_in
        .checked_mul(U256::from(FEE_DENOMINATOR_BPS - swap_fee_bps))
        .map(|v| v / U256::from(FEE_DENOMINATOR_BPS))
}

fn calc_out_given_in_equal_weights(
    balance_in: U256,
    balance_out: U256,
    amount_in: U256,
    swap_fee_bps: u64,
) -> Option<U256> {
    let amount_in_after_fee = fee_adjusted_amount_in(amount_in, swap_fee_bps)?;
    if amount_in_after_fee.is_zero() || balance_in.is_zero() || balance_out.is_zero() {
        return Some(U256::ZERO);
    }
    let denom = balance_in.checked_add(amount_in_after_fee)?;
    let numer = balance_out.checked_mul(amount_in_after_fee)?;
    Some(numer / denom)
}

fn calc_in_given_out_equal_weights(
    balance_in: U256,
    balance_out: U256,
    amount_out: U256,
    swap_fee_bps: u64,
) -> Option<U256> {
    if amount_out.is_zero() {
        return Some(U256::ZERO);
    }
    if amount_out >= balance_out || swap_fee_bps >= FEE_DENOMINATOR_BPS {
        return None;
    }
    let numer = balance_in.checked_mul(amount_out)?;
    let denom = balance_out.checked_sub(amount_out)?;
    let raw_in = numer.checked_div(denom)?.checked_add(U256::from(1u64))?;
    let fee_factor = U256::from(FEE_DENOMINATOR_BPS - swap_fee_bps);
    raw_in
        .checked_mul(U256::from(FEE_DENOMINATOR_BPS))
        .map(|v| v / fee_factor + U256::from(1u64))
}

/// Balancer weighted pool output quote.
///
/// `weight_*` are expected in 1e18 fixed-point format.
pub fn calc_out_given_in(
    balance_in: U256,
    weight_in: U256,
    balance_out: U256,
    weight_out: U256,
    amount_in: U256,
    swap_fee_bps: u64,
) -> U256 {
    if balance_in.is_zero()
        || balance_out.is_zero()
        || weight_in.is_zero()
        || weight_out.is_zero()
        || amount_in.is_zero()
    {
        return U256::ZERO;
    }

    if weight_in == weight_out {
        return calc_out_given_in_equal_weights(balance_in, balance_out, amount_in, swap_fee_bps)
            .unwrap_or(U256::ZERO);
    }

    let amount_in_after_fee = match fee_adjusted_amount_in(amount_in, swap_fee_bps) {
        Some(v) if !v.is_zero() => v,
        _ => return U256::ZERO,
    };

    let bi = match u256_to_f64(balance_in) {
        Some(v) if v > 0.0 => v,
        _ => return U256::ZERO,
    };
    let bo = match u256_to_f64(balance_out) {
        Some(v) if v > 0.0 => v,
        _ => return U256::ZERO,
    };
    let ai = match u256_to_f64(amount_in_after_fee) {
        Some(v) if v > 0.0 => v,
        _ => return U256::ZERO,
    };
    let wi = match u256_to_f64(weight_in) {
        Some(v) if v > 0.0 => v / WEIGHT_SCALE as f64,
        _ => return U256::ZERO,
    };
    let wo = match u256_to_f64(weight_out) {
        Some(v) if v > 0.0 => v / WEIGHT_SCALE as f64,
        _ => return U256::ZERO,
    };
    if wi <= 0.0 || wo <= 0.0 {
        return U256::ZERO;
    }

    // out = bo * (1 - (bi / (bi + ai))^(wi/wo))
    let ratio = (bi / (bi + ai)).max(POW_GUARD_MIN);
    let power = ratio.powf((wi / wo).max(POW_GUARD_MIN));
    let out_f64 = bo * (1.0 - power);
    let out = f64_floor_to_u256(out_f64).unwrap_or(U256::ZERO);
    out.min(balance_out)
}

/// Balancer weighted pool input quote (inverse path).
///
/// `weight_*` are expected in 1e18 fixed-point format.
pub fn calc_in_given_out(
    balance_in: U256,
    weight_in: U256,
    balance_out: U256,
    weight_out: U256,
    amount_out: U256,
    swap_fee_bps: u64,
) -> U256 {
    if balance_in.is_zero()
        || balance_out.is_zero()
        || weight_in.is_zero()
        || weight_out.is_zero()
        || amount_out.is_zero()
    {
        return U256::ZERO;
    }
    if amount_out >= balance_out || swap_fee_bps >= FEE_DENOMINATOR_BPS {
        return U256::ZERO;
    }

    if weight_in == weight_out {
        return calc_in_given_out_equal_weights(balance_in, balance_out, amount_out, swap_fee_bps)
            .unwrap_or(U256::ZERO);
    }

    let bi = match u256_to_f64(balance_in) {
        Some(v) if v > 0.0 => v,
        _ => return U256::ZERO,
    };
    let bo = match u256_to_f64(balance_out) {
        Some(v) if v > 0.0 => v,
        _ => return U256::ZERO,
    };
    let ao = match u256_to_f64(amount_out) {
        Some(v) if v > 0.0 => v,
        _ => return U256::ZERO,
    };
    let wi = match u256_to_f64(weight_in) {
        Some(v) if v > 0.0 => v / WEIGHT_SCALE as f64,
        _ => return U256::ZERO,
    };
    let wo = match u256_to_f64(weight_out) {
        Some(v) if v > 0.0 => v / WEIGHT_SCALE as f64,
        _ => return U256::ZERO,
    };
    if wi <= 0.0 || wo <= 0.0 {
        return U256::ZERO;
    }

    // in = bi * ((bo / (bo - ao))^(wo/wi) - 1) / (1 - fee)
    let base = bo / (bo - ao);
    let power = base.powf((wo / wi).max(POW_GUARD_MIN));
    let raw_in = bi * (power - 1.0);
    let fee_factor = 1.0 - (swap_fee_bps as f64 / FEE_DENOMINATOR_BPS as f64);
    if fee_factor <= 0.0 {
        return U256::ZERO;
    }
    f64_floor_to_u256((raw_in / fee_factor).ceil()).unwrap_or(U256::ZERO)
}

/// Symbolic envelope for Balancer weighted math.
///
/// For equal weights, this emits exact constant-product math.
/// For non-equal weights, it emits a bounded UF fallback with strict output limits.
pub fn calc_out_given_in_symbolic<'ctx>(
    ctx: &'ctx z3::Context,
    amount_in: &BV<'ctx>,
    balance_in: &BV<'ctx>,
    balance_out: &BV<'ctx>,
    weight_in: &BV<'ctx>,
    weight_out: &BV<'ctx>,
    swap_fee_bps: u64,
) -> (BV<'ctx>, Bool<'ctx>) {
    let zero = BV::from_u64(ctx, 0, 256);
    let fee_num = BV::from_u64(ctx, FEE_DENOMINATOR_BPS - swap_fee_bps, 256);
    let fee_den = BV::from_u64(ctx, FEE_DENOMINATOR_BPS, 256);
    let amount_in_after_fee = amount_in.bvmul(&fee_num).bvudiv(&fee_den);

    let out_cp = balance_out
        .bvmul(&amount_in_after_fee)
        .bvudiv(&balance_in.bvadd(&amount_in_after_fee));

    let uf_decl = z3::FuncDecl::new(
        ctx,
        "balancer_weighted_out_uf",
        &[
            &z3::Sort::bitvector(ctx, 256),
            &z3::Sort::bitvector(ctx, 256),
            &z3::Sort::bitvector(ctx, 256),
            &z3::Sort::bitvector(ctx, 256),
            &z3::Sort::bitvector(ctx, 256),
            &z3::Sort::bitvector(ctx, 256),
        ],
        &z3::Sort::bitvector(ctx, 256),
    );
    let out_uf = uf_decl
        .apply(&[
            amount_in,
            balance_in,
            balance_out,
            weight_in,
            weight_out,
            &BV::from_u64(ctx, swap_fee_bps, 256),
        ])
        .as_bv()
        .unwrap_or_else(|| zero.clone());

    let equal_weights = weight_in._eq(weight_out);
    let out = equal_weights.ite(&out_cp, &out_uf);
    let constraints = Bool::and(
        ctx,
        &[
            &balance_in.bvugt(&zero),
            &balance_out.bvugt(&zero),
            &weight_in.bvugt(&zero),
            &weight_out.bvugt(&zero),
            &out.bvule(balance_out),
            &equal_weights.implies(&out._eq(&out_cp)),
            &equal_weights.not().implies(&out_uf.bvule(balance_out)),
        ],
    );

    (out, constraints)
}

#[cfg(test)]
mod tests {
    use super::{calc_in_given_out, calc_out_given_in, calc_out_given_in_symbolic};
    use alloy::primitives::U256;
    use z3::{Config, Context, Solver};

    #[test]
    fn equal_weight_out_given_in_is_positive() {
        let w = U256::from(1_000_000_000_000_000_000u128);
        let out = calc_out_given_in(
            U256::from(1_000_000u64),
            w,
            U256::from(1_000_000u64),
            w,
            U256::from(10_000u64),
            30,
        );
        assert!(out > U256::ZERO);
    }

    #[test]
    fn in_given_out_increases_with_larger_desired_out() {
        let wi = U256::from(800_000_000_000_000_000u128);
        let wo = U256::from(200_000_000_000_000_000u128);
        let small = calc_in_given_out(
            U256::from(2_000_000u64),
            wi,
            U256::from(1_000_000u64),
            wo,
            U256::from(1_000u64),
            30,
        );
        let big = calc_in_given_out(
            U256::from(2_000_000u64),
            wi,
            U256::from(1_000_000u64),
            wo,
            U256::from(5_000u64),
            30,
        );
        assert!(big >= small);
    }

    #[test]
    fn symbolic_equal_weight_branch_is_sat() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let amount_in = z3::ast::BV::from_u64(&ctx, 10_000, 256);
        let balance_in = z3::ast::BV::from_u64(&ctx, 1_000_000, 256);
        let balance_out = z3::ast::BV::from_u64(&ctx, 1_000_000, 256);
        let weight = z3::ast::BV::from_u64(&ctx, 1_000_000, 256);

        let (out, c) = calc_out_given_in_symbolic(
            &ctx,
            &amount_in,
            &balance_in,
            &balance_out,
            &weight,
            &weight,
            30,
        );
        solver.assert(&c);
        solver.assert(&out.bvugt(&z3::ast::BV::from_u64(&ctx, 0, 256)));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }
}
