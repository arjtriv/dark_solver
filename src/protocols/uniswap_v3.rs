use crate::symbolic::utils::math::{extend_to_512, one, safe_div, val};
use z3::ast::{Array, Ast, Bool, BV};

pub struct MultiTickSwapResult<'ctx> {
    pub amount_out: BV<'ctx>,
    pub sqrt_price_x96: BV<'ctx>,
    pub liquidity: BV<'ctx>,
    pub amount_remaining: BV<'ctx>,
    pub ok: Bool<'ctx>,
}

fn q96_512<'ctx>(ctx: &'ctx z3::Context) -> BV<'ctx> {
    let n96 = val(ctx, 96);
    extend_to_512(ctx, &one(ctx)).bvshl(&extend_to_512(ctx, &n96))
}

fn div_rounding_up_512<'ctx>(ctx: &'ctx z3::Context, num: &BV<'ctx>, denom: &BV<'ctx>) -> BV<'ctx> {
    let zero = BV::from_u64(ctx, 0, 512);
    let one = BV::from_u64(ctx, 1, 512);
    let denom_is_zero = denom._eq(&zero);
    let q = num.bvudiv(denom);
    let r = num.bvurem(denom);
    let has_rem = r._eq(&zero).not();
    let q_plus = q.bvadd(&one);
    denom_is_zero.ite(&zero, &has_rem.ite(&q_plus, &q))
}

fn compute_fee_amount_on_target_reached<'ctx>(
    ctx: &'ctx z3::Context,
    amount_in: &BV<'ctx>,
    fee_pips: u64,
) -> BV<'ctx> {
    // feeAmount = ceil(amountIn * feePips / (1e6 - feePips))
    let fee = val(ctx, fee_pips);
    let denom = val(ctx, 1_000_000u64.saturating_sub(fee_pips));
    let fee_512 = extend_to_512(ctx, &fee);
    let denom_512 = extend_to_512(ctx, &denom);
    let ain_512 = extend_to_512(ctx, amount_in);
    div_rounding_up_512(ctx, &ain_512.bvmul(&fee_512), &denom_512).extract(255, 0)
}

fn amount_remaining_less_fee<'ctx>(
    ctx: &'ctx z3::Context,
    amount_in: &BV<'ctx>,
    fee_pips: u64,
) -> BV<'ctx> {
    let fee_multiplier = val(ctx, 1_000_000u64.saturating_sub(fee_pips));
    let fee_denominator = val(ctx, 1_000_000);
    let ain_512 = extend_to_512(ctx, amount_in);
    let fm_512 = extend_to_512(ctx, &fee_multiplier);
    let fd_512 = extend_to_512(ctx, &fee_denominator);
    safe_div(&ain_512.bvmul(&fm_512), &fd_512).extract(255, 0)
}

fn swap_step_exact_in<'ctx>(
    ctx: &'ctx z3::Context,
    sqrt_price_x96: &BV<'ctx>,
    sqrt_price_target_x96: &BV<'ctx>,
    liquidity: &BV<'ctx>,
    amount_remaining: &BV<'ctx>,
    zero_for_one: bool,
    fee_pips: u64,
) -> (
    BV<'ctx>,
    BV<'ctx>,
    BV<'ctx>,
    BV<'ctx>,
    Bool<'ctx>,
    Bool<'ctx>,
) {
    // Returns (sqrt_next, amount_in_used, amount_out, fee_amount, reached_target, ok)
    //
    // ok guards:
    // - liquidity != 0
    // - sqrt prices != 0 (avoid denom=0 in mul/div)
    let zero256 = BV::from_u64(ctx, 0, 256);
    let liq_ok = liquidity._eq(&zero256).not();
    let sqrt_ok = Bool::and(
        ctx,
        &[
            &sqrt_price_x96._eq(&zero256).not(),
            &sqrt_price_target_x96._eq(&zero256).not(),
        ],
    );
    let ok = Bool::and(ctx, &[&liq_ok, &sqrt_ok]);

    let q96 = q96_512(ctx);
    let amount_less_fee = amount_remaining_less_fee(ctx, amount_remaining, fee_pips);

    let sqrtp_512 = extend_to_512(ctx, sqrt_price_x96);
    let sqrtt_512 = extend_to_512(ctx, sqrt_price_target_x96);
    let liq_512 = extend_to_512(ctx, liquidity);

    let (amount_in_to_target_256, amount_out_to_target_256) = if zero_for_one {
        // token0 in, token1 out, sqrt decreases.
        let delta = sqrtp_512.bvsub(&sqrtt_512);
        let denom_prod = sqrtp_512.bvmul(&sqrtt_512);
        let numerator_in = liq_512.bvmul(&delta).bvmul(&q96);
        let amount_in_to_target =
            div_rounding_up_512(ctx, &numerator_in, &denom_prod).extract(255, 0);

        let amount_out_to_target = safe_div(&liq_512.bvmul(&delta), &q96).extract(255, 0);
        (amount_in_to_target, amount_out_to_target)
    } else {
        // token1 in, token0 out, sqrt increases.
        let delta = sqrtt_512.bvsub(&sqrtp_512);
        let amount_in_to_target =
            div_rounding_up_512(ctx, &liq_512.bvmul(&delta), &q96).extract(255, 0);

        let numerator_out = liq_512.bvmul(&q96).bvmul(&delta);
        let denom_prod = sqrtp_512.bvmul(&sqrtt_512);
        let amount_out_to_target = safe_div(&numerator_out, &denom_prod).extract(255, 0);
        (amount_in_to_target, amount_out_to_target)
    };

    let reached_target = amount_less_fee.bvuge(&amount_in_to_target_256);
    let fee_on_reach =
        compute_fee_amount_on_target_reached(ctx, &amount_in_to_target_256, fee_pips);

    let (sqrt_next_partial_512, amount_out_partial_256) = if zero_for_one {
        // sqrtNext = (L * sqrtP * Q96) / (L*Q96 + amount * sqrtP)
        let numerator = liq_512.bvmul(&sqrtp_512).bvmul(&q96);
        let denom = liq_512
            .bvmul(&q96)
            .bvadd(&extend_to_512(ctx, &amount_less_fee).bvmul(&sqrtp_512));
        let sqrt_next = safe_div(&numerator, &denom);
        let amount_out =
            safe_div(&liq_512.bvmul(&sqrtp_512.bvsub(&sqrt_next)), &q96).extract(255, 0);
        (sqrt_next, amount_out)
    } else {
        // sqrtNext = sqrtP + amount*Q96/L
        let delta_sqrt = safe_div(&extend_to_512(ctx, &amount_less_fee).bvmul(&q96), &liq_512);
        let sqrt_next = sqrtp_512.bvadd(&delta_sqrt);
        let numerator_out = liq_512.bvmul(&q96).bvmul(&delta_sqrt);
        let denom_prod = sqrtp_512.bvmul(&sqrt_next);
        let amount_out = safe_div(&numerator_out, &denom_prod).extract(255, 0);
        (sqrt_next, amount_out)
    };

    let sqrt_next = reached_target.ite(
        sqrt_price_target_x96,
        &sqrt_next_partial_512.extract(255, 0),
    );
    let amount_in_used = reached_target.ite(&amount_in_to_target_256, &amount_less_fee);
    let amount_out = reached_target.ite(&amount_out_to_target_256, &amount_out_partial_256);
    let fee_amount = reached_target.ite(&fee_on_reach, &amount_remaining.bvsub(&amount_less_fee));

    (
        sqrt_next,
        amount_in_used,
        amount_out,
        fee_amount,
        reached_target,
        ok,
    )
}

/// Multi-tick exact-input swap model (bounded unroll).
///
/// `sqrt_price_targets_x96[i]` is the next tick boundary sqrt price in the swap direction.
/// `liquidity_net[i]` is the tick's liquidityNet (unsigned magnitude). When crossing:
/// - price increases (one_for_zero): L := L + liquidityNet
/// - price decreases (zero_for_one): L := L - liquidityNet
#[allow(clippy::too_many_arguments)]
pub fn swap_exact_in_multi_tick<'ctx>(
    ctx: &'ctx z3::Context,
    amount_in: &BV<'ctx>,
    liquidity: &BV<'ctx>,
    sqrt_price_x96: &BV<'ctx>,
    zero_for_one: bool,
    fee_pips: u64,
    sqrt_price_targets_x96: &[BV<'ctx>],
    liquidity_net: &[BV<'ctx>],
) -> MultiTickSwapResult<'ctx> {
    const MAX_CROSSINGS: usize = 8;
    let steps = std::cmp::min(
        MAX_CROSSINGS,
        std::cmp::min(sqrt_price_targets_x96.len(), liquidity_net.len()),
    );

    let mut ok = Bool::from_bool(ctx, true);
    let mut active = Bool::from_bool(ctx, true);

    let mut sqrtp = sqrt_price_x96.clone();
    let mut liq = liquidity.clone();
    let mut amount_remaining = amount_in.clone();
    let mut amount_out_acc = BV::from_u64(ctx, 0, 256);

    for i in 0..steps {
        let target = &sqrt_price_targets_x96[i];
        let net = &liquidity_net[i];

        let (sqrt_next, amount_in_used, amount_out, fee_amount, reached, step_ok) =
            swap_step_exact_in(
                ctx,
                &sqrtp,
                target,
                &liq,
                &amount_remaining,
                zero_for_one,
                fee_pips,
            );

        // reached is only meaningful while active.
        let do_reach = Bool::and(ctx, &[&active, &reached]);
        let do_step = active.clone();

        // Liquidity update if we crossed this tick boundary.
        let (liq_next, liq_ok) = if zero_for_one {
            let no_underflow = liq.bvuge(net);
            (
                no_underflow.ite(&liq.bvsub(net), &BV::from_u64(ctx, 0, 256)),
                no_underflow,
            )
        } else {
            (liq.bvadd(net), Bool::from_bool(ctx, true))
        };
        ok = Bool::and(ctx, &[&ok, &step_ok, &do_reach.implies(&liq_ok)]);

        // amount_out_acc += (do_step ? amount_out : 0)
        let out_add = do_step.ite(&amount_out, &BV::from_u64(ctx, 0, 256));
        let next_acc = amount_out_acc.bvadd(&out_add);
        ok = Bool::and(ctx, &[&ok, &next_acc.bvuge(&amount_out_acc)]);
        amount_out_acc = next_acc;

        // Update remaining:
        // - if reached: subtract consumed+fee
        // - else if did step but not reached: terminate (remaining := 0)
        // - else (inactive): unchanged
        let spent = amount_in_used.bvadd(&fee_amount);
        ok = Bool::and(ctx, &[&ok, &spent.bvuge(&amount_in_used)]);
        let remaining_after_reach = amount_remaining.bvsub(&spent);
        let remaining_next = do_reach.ite(
            &remaining_after_reach,
            &do_step.ite(&BV::from_u64(ctx, 0, 256), &amount_remaining),
        );

        // Update sqrt price:
        let sqrt_next_final = do_step.ite(&sqrt_next, &sqrtp);
        // Update liquidity only when we cross.
        let liq_next_final = do_reach.ite(&liq_next, &liq);

        sqrtp = sqrt_next_final;
        liq = liq_next_final;
        amount_remaining = remaining_next;

        // Continue only if we crossed.
        active = do_reach;
    }

    MultiTickSwapResult {
        amount_out: amount_out_acc,
        sqrt_price_x96: sqrtp,
        liquidity: liq,
        amount_remaining,
        ok,
    }
}

/// Symbolic Uniswap V3 Swap Step (Single Tick)
///
/// Models the math for a swap within a single tick range.
/// Supports both ZeroForOne (x -> y) and OneForZero (y -> x).
///
/// Core Formulas:
/// 1. ZeroForOne (Price decreases):
///    sqrtP_next = (L * sqrtP) / (L + amount_in * sqrtP / 2^96)
///    amount_out = L * (sqrtP - sqrtP_next) / 2^96
///
/// 2. OneForZero (Price increases):
///    sqrtP_next = sqrtP + (amount_in * 2^96) / L
///    amount_out = L * (1/sqrtP - 1/sqrtP_next) * 2^96  <-- Wait, this implies inverse.
///    Simpler: amount_out = L * (1/sqrtP - 1/sqrtP_next)
///    Actually derived from: delta_x = L * (1/sqrtP - 1/sqrtP_next)
///
/// All intermediate multiplications use 512-bit extension to prevent overflow.
pub fn get_amount_out<'ctx>(
    ctx: &'ctx z3::Context,
    amount_in: &BV<'ctx>,
    liquidity: &BV<'ctx>,
    sqrt_price_x96: &BV<'ctx>,
    zero_for_one: bool,
    fee_pips: u64,
) -> BV<'ctx> {
    // 1. Calculate Amount Remaining after Fee
    // fee is in pips (e.g. 3000 = 0.3%)
    // amount_remaining = amount_in * (1e6 - fee) / 1e6
    let fee_multiplier = val(ctx, 1_000_000 - fee_pips);
    let fee_denominator = val(ctx, 1_000_000);

    // 512-bit extension for fee calculation
    let ain_512 = extend_to_512(ctx, amount_in);
    let fm_512 = extend_to_512(ctx, &fee_multiplier);
    let fd_512 = extend_to_512(ctx, &fee_denominator);

    let amount_rem_512 = ain_512.bvmul(&fm_512).bvudiv(&fd_512);
    // Project back to 512 for further calc, but we can treat it as the "effective input"
    // Since amount_in is 256, amount_rem fits in 256, but we keep 512 for safety in next steps?
    // Actually, V2 implementation projects back to 256 if needed, but here we feed it into 512 mul.

    let n96 = val(ctx, 96);
    let q96_512 = extend_to_512(ctx, &one(ctx)).bvshl(&extend_to_512(ctx, &n96));

    let liq_512 = extend_to_512(ctx, liquidity);
    let sqrtp_512 = extend_to_512(ctx, sqrt_price_x96);

    if zero_for_one {
        // ZeroForOne: Input x, Output y.
        // Formula: sqrtNext = (L * sqrtP) / (L + amount * sqrtP / Q96)
        // Refactored to avoid division by Q96 in denominator:
        // sqrtNext = (L * sqrtP * Q96) / (L * Q96 + amount * sqrtP)

        let numerator = liq_512.bvmul(&sqrtp_512).bvmul(&q96_512);
        let term1 = liq_512.bvmul(&q96_512);
        let term2 = amount_rem_512.bvmul(&sqrtp_512); // amount_rem is already 512
        let denominator = term1.bvadd(&term2);

        // Overflow guard for denominator? term1 can be approx 2^128 * 2^96 = 2^224. term2 approx 2^256 * 2^96 = 2^352.
        // Max 512 bits. Safe.

        let sqrt_next_512 = safe_div(&numerator, &denominator);

        // Output y = L * (sqrtP - sqrtNext) / Q96
        // Use full 512 precision
        // Note: sqrtP is the CURRENT price (higher). sqrtNext is NEW price (lower).
        let delta_sqrt = sqrtp_512.bvsub(&sqrt_next_512);
        let amount_out_512 = liq_512.bvmul(&delta_sqrt).bvudiv(&q96_512);

        amount_out_512.extract(255, 0)
    } else {
        // OneForZero: Input y, Output x.
        // Formula: sqrtNext = sqrtP + (amount * Q96) / L

        let amount_shifted = amount_rem_512.bvmul(&q96_512);
        let delta_sqrt = safe_div(&amount_shifted, &liq_512);
        let sqrt_next_512 = sqrtp_512.bvadd(&delta_sqrt);

        // Output x = L * (1/sqrtP - 1/sqrtNext)
        // = L * ( (sqrtNext - sqrtP) / (sqrtP * sqrtNext) ) * Q96^?
        // Wait, standard V3 formula for delta x:
        // delta_x = L * (sqrtNext - sqrtP) / (sqrtNext * sqrtP) ? No.
        // delta_x = L * (1/sqrtP - 1/sqrtNext)
        // = L * ( (sqrtNext - sqrtP) / (sqrtP * sqrtNext) ) * Q96^2 ?
        // 1/sqrtP is encoded as Q96 / sqrtP.
        // So delta_x = L * ( Q96/sqrtP - Q96/sqrtNext )
        // = L * Q96 * (sqrtNext - sqrtP) / (sqrtP * sqrtNext)

        // Let's compute directly using big int division to be safe and match protocol
        // delta_x = (L * Q96 * (sqrtNext - sqrtP)) / (sqrtP * sqrtNext)

        // We know (sqrtNext - sqrtP) is exactly `delta_sqrt`.
        // So: (L * Q96 * delta_sqrt) / (sqrtP * sqrtNext)

        let numerator = liq_512.bvmul(&q96_512).bvmul(&delta_sqrt);
        let denom_prod = sqrtp_512.bvmul(&sqrt_next_512);

        let amount_out_512 = safe_div(&numerator, &denom_prod);

        amount_out_512.extract(255, 0)
    }
}

fn first_set_bit_lsb<'ctx>(ctx: &'ctx z3::Context, word: &BV<'ctx>) -> (BV<'ctx>, Bool<'ctx>) {
    let mut found = Bool::from_bool(ctx, false);
    let mut index = BV::from_u64(ctx, 0, 256);
    for i in 0..256u64 {
        let bit_mask = BV::from_u64(ctx, 1, 256).bvshl(&BV::from_u64(ctx, i, 256));
        let bit_is_set = word.bvand(&bit_mask)._eq(&bit_mask);
        let choose = Bool::and(ctx, &[&bit_is_set, &found.not()]);
        index = choose.ite(&BV::from_u64(ctx, i, 256), &index);
        found = Bool::or(ctx, &[&found, &bit_is_set]);
    }
    (index, found)
}

fn first_set_bit_msb<'ctx>(ctx: &'ctx z3::Context, word: &BV<'ctx>) -> (BV<'ctx>, Bool<'ctx>) {
    let mut found = Bool::from_bool(ctx, false);
    let mut index = BV::from_u64(ctx, 0, 256);
    for i in (0..256u64).rev() {
        let bit_mask = BV::from_u64(ctx, 1, 256).bvshl(&BV::from_u64(ctx, i, 256));
        let bit_is_set = word.bvand(&bit_mask)._eq(&bit_mask);
        let choose = Bool::and(ctx, &[&bit_is_set, &found.not()]);
        index = choose.ite(&BV::from_u64(ctx, i, 256), &index);
        found = Bool::or(ctx, &[&found, &bit_is_set]);
    }
    (index, found)
}

pub fn symbolic_tick_bitmap<'ctx>(ctx: &'ctx z3::Context, name: &str) -> Array<'ctx> {
    let domain = z3::Sort::bitvector(ctx, 256);
    let range = z3::Sort::bitvector(ctx, 256);
    Array::new_const(ctx, name, &domain, &range)
}

/// Finds the next initialized tick within the current bitmap word.
/// This performs a one-word symbolic jump using bit masks + priority-encode,
/// avoiding tick-by-tick loops.
pub fn next_initialized_tick_within_one_word<'ctx>(
    ctx: &'ctx z3::Context,
    tick_bitmap: &Array<'ctx>,
    current_tick: &BV<'ctx>,
    tick_spacing: u64,
    lte: bool,
) -> (BV<'ctx>, Bool<'ctx>) {
    let spacing = BV::from_u64(ctx, tick_spacing.max(1), 256);
    let one_bv = BV::from_u64(ctx, 1, 256);
    let shift_8 = BV::from_u64(ctx, 8, 256);

    // For the "gt" branch we start from compressed + 1, matching UniV3's next-tick semantics.
    let compressed_raw = current_tick.bvsdiv(&spacing);
    let compressed = if lte {
        compressed_raw
    } else {
        compressed_raw.bvadd(&one_bv)
    };

    let word_pos = compressed.bvashr(&shift_8);
    let bit_pos = compressed.bvand(&BV::from_u64(ctx, 0xff, 256));
    let word = tick_bitmap
        .select(&word_pos)
        .as_bv()
        .unwrap_or_else(|| BV::from_u64(ctx, 0, 256));

    let bit_pos_plus_one = bit_pos.bvadd(&one_bv);
    let mask_lte = one_bv.bvshl(&bit_pos_plus_one).bvsub(&one_bv);
    let lower_mask = one_bv.bvshl(&bit_pos).bvsub(&one_bv);
    let mask_gt = lower_mask.bvnot();

    let masked = if lte {
        word.bvand(&mask_lte)
    } else {
        word.bvand(&mask_gt)
    };

    let word_base = word_pos.bvshl(&shift_8);
    let (idx, found) = if lte {
        first_set_bit_msb(ctx, &masked)
    } else {
        first_set_bit_lsb(ctx, &masked)
    };

    let fallback = if lte {
        word_base.clone()
    } else {
        word_base.bvadd(&BV::from_u64(ctx, 255, 256))
    };
    let next_compressed = found.ite(&word_base.bvadd(&idx), &fallback);
    let next_tick = extend_to_512(ctx, &next_compressed)
        .bvmul(&extend_to_512(ctx, &spacing))
        .extract(255, 0);
    (next_tick, found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_next_initialized_tick_lte_word_jump() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let base = symbolic_tick_bitmap(&ctx, "tick_bitmap_lte");
        let word_val = BV::from_u64(&ctx, (1u64 << 5) | (1u64 << 12), 256);
        let bitmap = base.store(&BV::from_u64(&ctx, 0, 256), &word_val);

        let current_tick = BV::from_u64(&ctx, 10, 256);
        let (next_tick, found) =
            next_initialized_tick_within_one_word(&ctx, &bitmap, &current_tick, 1, true);

        solver.assert(&found);
        solver.assert(&next_tick._eq(&BV::from_u64(&ctx, 5, 256)));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_next_initialized_tick_gt_word_jump() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let base = symbolic_tick_bitmap(&ctx, "tick_bitmap_gt");
        let word_val = BV::from_u64(&ctx, (1u64 << 5) | (1u64 << 12), 256);
        let bitmap = base.store(&BV::from_u64(&ctx, 0, 256), &word_val);

        let current_tick = BV::from_u64(&ctx, 10, 256);
        let (next_tick, found) =
            next_initialized_tick_within_one_word(&ctx, &bitmap, &current_tick, 1, false);

        solver.assert(&found);
        solver.assert(&next_tick._eq(&BV::from_u64(&ctx, 12, 256)));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_next_initialized_tick_fallback_when_word_empty() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let bitmap = symbolic_tick_bitmap(&ctx, "tick_bitmap_empty");
        let current_tick = BV::from_u64(&ctx, 77, 256);
        let (next_tick, found) =
            next_initialized_tick_within_one_word(&ctx, &bitmap, &current_tick, 1, true);

        solver.assert(&found.not());
        solver.assert(&next_tick._eq(&BV::from_u64(&ctx, 0, 256)));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }
}
