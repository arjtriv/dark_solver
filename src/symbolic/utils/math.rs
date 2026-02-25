//! Canonical location for shared symbolic math helpers.
//! Rule: generic reusable symbolic arithmetic/bitvector helpers belong in this file.

use z3::ast::{Ast, BV};

/// Safe Symbolic Division (Unsigned)
/// Returns 0 if denominator is 0, else a / b
/// Width-polymorphic: derives zero from operand bit-width (supports 256 AND 512-bit).
pub fn safe_div<'ctx>(a: &BV<'ctx>, b: &BV<'ctx>) -> BV<'ctx> {
    let ctx = a.get_ctx();
    let width = b.get_size();
    let zero = BV::from_u64(ctx, 0, width);
    let is_zero = b._eq(&zero);
    is_zero.ite(&zero, &a.bvudiv(b))
}

/// Safe Symbolic Remainder (Unsigned)
/// Returns 0 if denominator is 0, else a % b
/// Width-polymorphic: derives zero from operand bit-width (supports 256 AND 512-bit).
pub fn safe_rem<'ctx>(a: &BV<'ctx>, b: &BV<'ctx>) -> BV<'ctx> {
    let ctx = a.get_ctx();
    let width = b.get_size();
    let zero = BV::from_u64(ctx, 0, width);
    let is_zero = b._eq(&zero);
    is_zero.ite(&zero, &a.bvurem(b))
}

/// Safe Symbolic Division (Signed)
/// Returns 0 if denominator is 0, else a / b (signed)
/// Note: EVM has special case for INT_MIN / -1, but Z3 handles standard BVSREM.
/// We strictly enforce the "div by zero -> 0" rule for EVM compatibility.
/// Width-polymorphic: derives zero from operand bit-width.
pub fn safe_sdiv<'ctx>(a: &BV<'ctx>, b: &BV<'ctx>) -> BV<'ctx> {
    let ctx = a.get_ctx();
    let width = b.get_size();
    let zero = BV::from_u64(ctx, 0, width);
    let is_zero = b._eq(&zero);
    is_zero.ite(&zero, &a.bvsdiv(b))
}

/// Safe Symbolic Remainder (Signed)
/// Returns 0 if denominator is 0, else a % b (signed)
/// Width-polymorphic: derives zero from operand bit-width.
pub fn safe_srem<'ctx>(a: &BV<'ctx>, b: &BV<'ctx>) -> BV<'ctx> {
    let ctx = a.get_ctx();
    let width = b.get_size();
    let zero = BV::from_u64(ctx, 0, width);
    let is_zero = b._eq(&zero);
    is_zero.ite(&zero, &a.bvsrem(b))
}

/// Zero-extend a 256-bit BV to 512-bit
pub fn extend_to_512<'ctx>(ctx: &'ctx z3::Context, val: &BV<'ctx>) -> BV<'ctx> {
    let zero_256 = zero(ctx);
    zero_256.concat(val)
}

/// Constant: 0 (256-bit)
pub fn zero<'ctx>(ctx: &'ctx z3::Context) -> BV<'ctx> {
    BV::from_u64(ctx, 0, 256)
}

/// Constant: 1 (256-bit)
pub fn one<'ctx>(ctx: &'ctx z3::Context) -> BV<'ctx> {
    BV::from_u64(ctx, 1, 256)
}

/// Constant: WAD (10^18)
pub fn wad<'ctx>(ctx: &'ctx z3::Context) -> BV<'ctx> {
    BV::from_u64(ctx, 1_000_000_000_000_000_000, 256)
}

/// Constant: Arbitrary u64 (256-bit)
pub fn val<'ctx>(ctx: &'ctx z3::Context, v: u64) -> BV<'ctx> {
    BV::from_u64(ctx, v, 256)
}

/// Canonical EVM address normalization: keep low 160 bits, zero high 96 bits.
pub fn clean_address_word<'ctx>(addr: &BV<'ctx>) -> BV<'ctx> {
    addr.extract(159, 0).zero_ext(96)
}

/// Resolve a symbolic length BV to a concrete loop bound, clamped to `limit`.
/// If the BV is symbolic (non-concrete), defaults to `limit` to avoid silent data loss.
pub fn bounded_len(sym_len: &BV, limit: usize) -> usize {
    let len_u: usize = crate::symbolic::z3_ext::u256_from_bv(sym_len)
        .and_then(|v| v.try_into().ok())
        .unwrap_or(limit);
    std::cmp::min(len_u, limit)
}

/// Symbolic Exponentiation (EVM EXP Opcode)
/// Follows "Correctness > Speed" 256-bit iteration loop.
pub fn symbolic_exp<'ctx>(
    ctx: &'ctx z3::Context,
    base: &BV<'ctx>,
    exponent: &BV<'ctx>,
) -> BV<'ctx> {
    // OPTIMIZATION: Check for Concrete Exponent (Common Case)
    if let Some(exp_u64) =
        crate::symbolic::z3_ext::u256_from_bv(exponent).and_then(|v| u64::try_from(v).ok())
    {
        let mut result = BV::from_u64(ctx, 1, 256);
        let mut b = base.clone();
        // Exponentiation by squaring
        let mut e = exp_u64;
        while e > 0 {
            if e % 2 == 1 {
                result = result.bvmul(&b);
            }
            b = b.bvmul(&b);
            e /= 2;
        }
        result
    } else {
        // SYMBOLIC EXP EXPONENTIATION
        // We must iterate 256 times to ensure mathematical soundness.
        let one = BV::from_u64(ctx, 1, 256);
        let mut generic_res = one.clone();
        let mut current_base = base.clone();

        for i in 0..256 {
            let bit = exponent.extract(i as u32, i as u32);
            let is_set = bit._eq(&BV::from_u64(ctx, 1, 1));

            let new_res = generic_res.bvmul(&current_base);
            generic_res = is_set.ite(&new_res, &generic_res);

            if i < 255 {
                current_base = current_base.bvmul(&current_base);
            }
        }
        generic_res
    }
}

/// Symbolic SIGNEXTEND (EVM SIGNEXTEND Opcode)
pub fn symbolic_signextend<'ctx>(ctx: &'ctx z3::Context, b: &BV<'ctx>, x: &BV<'ctx>) -> BV<'ctx> {
    let mut final_res = x.clone();
    for i in 0..31 {
        let idx = i as u64;
        let check_b = b._eq(&BV::from_u64(ctx, idx, 256));
        let low_bits = (idx + 1) * 8;
        let high_bits = 256 - low_bits;
        let low_part = x.extract((low_bits - 1) as u32, 0);
        let sign_bit = low_part.extract((low_bits - 1) as u32, (low_bits - 1) as u32);
        let is_neg = sign_bit._eq(&BV::from_u64(ctx, 1, 1));
        let zero_high = BV::from_u64(ctx, 0, high_bits as u32);
        let one_high = zero_high.bvnot();
        let high_part = is_neg.ite(&one_high, &zero_high);
        let candidate = high_part.concat(&low_part);
        final_res = check_b.ite(&candidate, &final_res);
    }
    final_res
}

/// Symbolic BYTE (EVM BYTE Opcode)
pub fn symbolic_byte<'ctx>(ctx: &'ctx z3::Context, i: &BV<'ctx>, val: &BV<'ctx>) -> BV<'ctx> {
    let n8 = BV::from_u64(ctx, 8, 256);
    let n31 = BV::from_u64(ctx, 31, 256);
    let n32 = BV::from_u64(ctx, 32, 256);
    let ffs = BV::from_u64(ctx, 0xff, 256);

    let out_of_bounds = i.bvuge(&n32);
    let shift = n31.bvsub(i).bvmul(&n8);
    let calculated = val.bvlshr(&shift).bvand(&ffs);

    out_of_bounds.ite(&zero(ctx), &calculated)
}
