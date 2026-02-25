//! Anchor Test: Oracle-Spot Discrepancy Probe
//!
//! This anchor locks the probe semantics:
//! 1) Oracle reference must remain within a configured sanity width of pre-manip spot.
//! 2) Manipulated spot must deviate from oracle by at least a discrepancy threshold.

use dark_solver::symbolic::utils::math::{extend_to_512, val};
use z3::ast::{Bool, BV};
use z3::{Config, Context, SatResult, Solver};

fn normalize_price_component<'ctx>(value: &BV<'ctx>) -> BV<'ctx> {
    value.extract(111, 0).zero_ext(144)
}

fn ratio_gap_exceeds_bps<'ctx>(
    ctx: &'ctx Context,
    left_num: &BV<'ctx>,
    left_den: &BV<'ctx>,
    right_num: &BV<'ctx>,
    right_den: &BV<'ctx>,
    min_bps: u64,
) -> Bool<'ctx> {
    let lnum = normalize_price_component(left_num);
    let lden = normalize_price_component(left_den);
    let rnum = normalize_price_component(right_num);
    let rden = normalize_price_component(right_den);

    let lhs = extend_to_512(ctx, &lnum).bvmul(&extend_to_512(ctx, &rden));
    let rhs = extend_to_512(ctx, &rnum).bvmul(&extend_to_512(ctx, &lden));

    let lhs_gt_rhs = lhs.bvugt(&rhs);
    let hi = lhs_gt_rhs.ite(&lhs, &rhs);
    let lo = lhs_gt_rhs.ite(&rhs, &lhs);

    let scale = extend_to_512(ctx, &val(ctx, 10_000));
    let threshold = extend_to_512(ctx, &val(ctx, 10_000u64.saturating_add(min_bps)));
    hi.bvmul(&scale).bvugt(&lo.bvmul(&threshold))
}

fn ratio_gap_within_bps<'ctx>(
    ctx: &'ctx Context,
    left_num: &BV<'ctx>,
    left_den: &BV<'ctx>,
    right_num: &BV<'ctx>,
    right_den: &BV<'ctx>,
    max_bps: u64,
) -> Bool<'ctx> {
    let lnum = normalize_price_component(left_num);
    let lden = normalize_price_component(left_den);
    let rnum = normalize_price_component(right_num);
    let rden = normalize_price_component(right_den);

    let lhs = extend_to_512(ctx, &lnum).bvmul(&extend_to_512(ctx, &rden));
    let rhs = extend_to_512(ctx, &rnum).bvmul(&extend_to_512(ctx, &lden));

    let lhs_gt_rhs = lhs.bvugt(&rhs);
    let hi = lhs_gt_rhs.ite(&lhs, &rhs);
    let lo = lhs_gt_rhs.ite(&rhs, &lhs);

    let scale = extend_to_512(ctx, &val(ctx, 10_000));
    let tolerance = extend_to_512(ctx, &val(ctx, 10_000u64.saturating_add(max_bps)));
    hi.bvmul(&scale).bvule(&lo.bvmul(&tolerance))
}

#[test]
fn test_oracle_spot_probe_sat_for_sane_oracle_and_large_manip_gap() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // Baseline spot: 1.0
    let base_num = BV::from_u64(&ctx, 1_000, 256);
    let base_den = BV::from_u64(&ctx, 1_000, 256);

    // Manipulated spot: 0.65 (35% move)
    let manip_num = BV::from_u64(&ctx, 650, 256);
    let manip_den = BV::from_u64(&ctx, 1_000, 256);

    // Oracle remains sane around baseline.
    let oracle_num = BV::from_u64(&ctx, 1_004, 256);
    let oracle_den = BV::from_u64(&ctx, 1_000, 256);
    solver.assert(&ratio_gap_within_bps(
        &ctx,
        &oracle_num,
        &oracle_den,
        &base_num,
        &base_den,
        80,
    ));

    // But manipulated spot diverges enough from oracle.
    solver.assert(&ratio_gap_exceeds_bps(
        &ctx,
        &manip_num,
        &manip_den,
        &oracle_num,
        &oracle_den,
        250,
    ));

    assert_eq!(solver.check(), SatResult::Sat);
}

#[test]
fn test_oracle_spot_probe_unsat_when_oracle_violates_sanity_width() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // Baseline spot: 1.0
    let base_num = BV::from_u64(&ctx, 1_000, 256);
    let base_den = BV::from_u64(&ctx, 1_000, 256);

    // Force oracle 20% away from baseline (outside 80 bps sanity width).
    let oracle_num = BV::from_u64(&ctx, 1_200, 256);
    let oracle_den = BV::from_u64(&ctx, 1_000, 256);
    solver.assert(&ratio_gap_within_bps(
        &ctx,
        &oracle_num,
        &oracle_den,
        &base_num,
        &base_den,
        80,
    ));

    assert_eq!(solver.check(), SatResult::Unsat);
}
