use crate::symbolic::utils::math::{extend_to_512, safe_div, val};
use crate::utils::constants::{UNISWAP_V2_FEE_DENOMINATOR, UNISWAP_V2_FEE_MULTIPLIER};
use z3::ast::{Ast, BV};

/// Formal model of Uniswap V2 constant product formula: dy = (dx * 997 * y) / (1000 * x + dx * 997)
/// Arithmetic in 512-bit to prevent overflow (same pattern as ADDMOD/MULMOD in arithmetic.rs).
/// Reserves clamped to 112 bits (UniV2 uint112) — any bits above 112 are unreachable on-chain.
/// Max numerator after clamp: 2^(256+10+112) = 2^378 < 2^512. Overflow-proof permanently.
pub fn get_amount_out<'ctx>(
    amount_in: &BV<'ctx>,
    reserve_in: &BV<'ctx>,
    reserve_out: &BV<'ctx>,
) -> BV<'ctx> {
    let ctx = amount_in.get_ctx();
    let n997 = val(ctx, UNISWAP_V2_FEE_MULTIPLIER);
    let n1000 = val(ctx, UNISWAP_V2_FEE_DENOMINATOR);

    // Clamp reserves to uint112 (UniV2 physical max), then extend to 512-bit.
    // Bits above 112 cannot exist on-chain — clamping prevents false positives
    // from impossible reserve values while keeping Z3 constraints tight.
    let rin_512 = reserve_in.extract(111, 0).zero_ext(400); // 112 → 512
    let rout_512 = reserve_out.extract(111, 0).zero_ext(400); // 112 → 512
    let ain_512 = extend_to_512(ctx, amount_in);
    let fee_512 = extend_to_512(ctx, &n997);
    let base_512 = extend_to_512(ctx, &n1000);

    let amount_in_with_fee_512 = ain_512.bvmul(&fee_512);
    let numerator_512 = amount_in_with_fee_512.bvmul(&rout_512);
    let denominator_512 = rin_512.bvmul(&base_512).bvadd(&amount_in_with_fee_512);

    safe_div(&numerator_512, &denominator_512).extract(255, 0)
}
