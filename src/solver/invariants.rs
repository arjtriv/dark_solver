//! Triple Gate Formal Specification
//!
//! A candidate exploit model is admissible iff:
//!     Gate := Solvency AND PriceSanity AND KConstraint
//!
//! Solvency:
//!     final_attacker_eth >= flash_loan_amount
//!
//! PriceSanity:
//!     For each manipulated pair reserve state (r0_after, r1_after):
//!       1) r0_after and r1_after are positive.
//!       2) r0_after and r1_after fit uint112 bounds.
//!       3) If baseline reserves are known, ratio drift is bounded by max_price_sanity_bps.
//!
//! KConstraint:
//!     For each pair with baseline reserves:
//!       k_after >= k_before
//!     where k values are computed in 512-bit space to avoid modular wrap-around artifacts.

use std::collections::HashMap;

use revm::db::CacheDB;
use revm::primitives::{Address, U256};
use revm::Database;
use z3::ast::{Ast, Bool, BV};
use z3::Context;

use crate::fork_db::ForkDB;
use crate::symbolic::state::SymbolicMachine;
use crate::symbolic::utils::math::{extend_to_512, val, zero};
use crate::symbolic::z3_ext::bv_from_u256;

const UNIV2_RESERVES_SLOT: u64 = 8;
const RESERVE_BITS: u32 = 112;
const DEFAULT_PRICE_SANITY_MAX_BPS: u64 = 250_000; // 2500%

fn reserve_mask_112() -> U256 {
    (U256::from(1u64) << RESERVE_BITS) - U256::from(1u64)
}

fn decode_univ2_reserves(word: U256) -> (U256, U256) {
    let mask = reserve_mask_112();
    let reserve0 = word & mask;
    let reserve1 = (word >> RESERVE_BITS) & mask;
    (reserve0, reserve1)
}

pub(crate) fn normalize_price_component<'ctx>(value: &BV<'ctx>) -> BV<'ctx> {
    value.extract(111, 0).zero_ext(144)
}

pub(crate) fn ratio_gap_exceeds_bps<'ctx>(
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

pub(crate) fn ratio_gap_within_bps<'ctx>(
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

#[derive(Debug, Clone)]
pub struct GlobalInvariantChecker {
    pub max_price_sanity_bps: u64,
    reserve_cache: HashMap<Address, (U256, U256)>,
}

impl Default for GlobalInvariantChecker {
    fn default() -> Self {
        let max_price_sanity_bps = std::env::var("GLOBAL_PRICE_SANITY_MAX_BPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_PRICE_SANITY_MAX_BPS);
        Self {
            max_price_sanity_bps,
            reserve_cache: HashMap::new(),
        }
    }
}

impl GlobalInvariantChecker {
    fn baseline_reserves<'ctx>(
        &mut self,
        ctx: &'ctx Context,
        db: &mut CacheDB<ForkDB>,
        pair: Address,
    ) -> Option<(BV<'ctx>, BV<'ctx>)> {
        if let Some((r0, r1)) = self.reserve_cache.get(&pair).copied() {
            return Some((bv_from_u256(ctx, r0), bv_from_u256(ctx, r1)));
        }

        let packed = db.storage(pair, U256::from(UNIV2_RESERVES_SLOT)).ok()?;
        let reserves = decode_univ2_reserves(packed);
        self.reserve_cache.insert(pair, reserves);
        Some((bv_from_u256(ctx, reserves.0), bv_from_u256(ctx, reserves.1)))
    }

    pub fn build_constraints<'ctx>(
        &mut self,
        ctx: &'ctx Context,
        machine: &SymbolicMachine<'ctx>,
        db: &mut CacheDB<ForkDB>,
        attacker: Address,
        flash_loan_amount: &BV<'ctx>,
    ) -> Bool<'ctx> {
        let mut baseline_reserves: HashMap<Address, (BV<'ctx>, BV<'ctx>)> = HashMap::new();
        for pair in machine.manipulated_reserves.keys() {
            if let Some((r0, r1)) = self.baseline_reserves(ctx, db, *pair) {
                baseline_reserves.insert(*pair, (r0, r1));
            }
        }

        self.build_constraints_with_baselines(
            ctx,
            machine,
            attacker,
            flash_loan_amount,
            &baseline_reserves,
        )
    }

    pub fn build_constraints_with_baselines<'ctx>(
        &self,
        ctx: &'ctx Context,
        machine: &SymbolicMachine<'ctx>,
        attacker: Address,
        flash_loan_amount: &BV<'ctx>,
        baseline_reserves: &HashMap<Address, (BV<'ctx>, BV<'ctx>)>,
    ) -> Bool<'ctx> {
        let solvency = if let Some(final_balance) = machine.balance_overrides.get(&attacker) {
            final_balance.bvuge(flash_loan_amount)
        } else {
            Bool::from_bool(ctx, false)
        };

        let mut price_sanity = Bool::from_bool(ctx, true);
        let mut k_constraint = Bool::from_bool(ctx, true);
        let zero_hi = BV::from_u64(ctx, 0, 144);
        let zero_word = zero(ctx);

        for (pair, (r0_after_raw, r1_after_raw)) in &machine.manipulated_reserves {
            let finite_r0 = r0_after_raw.extract(255, RESERVE_BITS)._eq(&zero_hi);
            let finite_r1 = r1_after_raw.extract(255, RESERVE_BITS)._eq(&zero_hi);
            let positive = Bool::and(
                ctx,
                &[
                    &r0_after_raw.bvugt(&zero_word),
                    &r1_after_raw.bvugt(&zero_word),
                ],
            );
            let mut pair_price_sanity = Bool::and(ctx, &[&finite_r0, &finite_r1, &positive]);

            let r0_after = normalize_price_component(r0_after_raw);
            let r1_after = normalize_price_component(r1_after_raw);

            if let Some((r0_before, r1_before)) = baseline_reserves.get(pair) {
                let bounded_drift = ratio_gap_within_bps(
                    ctx,
                    &r1_after,
                    &r0_after,
                    r1_before,
                    r0_before,
                    self.max_price_sanity_bps,
                );
                pair_price_sanity = Bool::and(ctx, &[&pair_price_sanity, &bounded_drift]);

                let k_after = extend_to_512(ctx, &r0_after).bvmul(&extend_to_512(ctx, &r1_after));
                let k_before = extend_to_512(ctx, &normalize_price_component(r0_before))
                    .bvmul(&extend_to_512(ctx, &normalize_price_component(r1_before)));
                let pair_k_constraint = k_after.bvuge(&k_before);
                k_constraint = Bool::and(ctx, &[&k_constraint, &pair_k_constraint]);
            }

            price_sanity = Bool::and(ctx, &[&price_sanity, &pair_price_sanity]);
        }

        Bool::and(ctx, &[&solvency, &price_sanity, &k_constraint])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    use crate::solver::setup::ATTACKER;
    use crate::symbolic::state::SymbolicMachine;
    use crate::symbolic::z3_ext::configure_solver;

    #[test]
    fn test_triple_gate_unsat_when_insolvent() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        configure_solver(&ctx, &solver);

        let mut machine = SymbolicMachine::new(&ctx, &solver, None);
        machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 99, 256));
        let loan = BV::from_u64(&ctx, 100, 256);

        let checker = GlobalInvariantChecker::default();
        let baseline = HashMap::new();
        let gate =
            checker.build_constraints_with_baselines(&ctx, &machine, ATTACKER, &loan, &baseline);
        solver.assert(&gate);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_triple_gate_unsat_when_k_decreases() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        configure_solver(&ctx, &solver);

        let pair = Address::from([0x11; 20]);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);
        machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 10_000, 256));
        machine.manipulated_reserves.insert(
            pair,
            (BV::from_u64(&ctx, 1_000, 256), BV::from_u64(&ctx, 200, 256)),
        );
        let loan = BV::from_u64(&ctx, 100, 256);

        let mut baseline = HashMap::new();
        baseline.insert(
            pair,
            (
                BV::from_u64(&ctx, 1_000, 256),
                BV::from_u64(&ctx, 1_000, 256),
            ),
        );

        let checker = GlobalInvariantChecker::default();
        let gate =
            checker.build_constraints_with_baselines(&ctx, &machine, ATTACKER, &loan, &baseline);
        solver.assert(&gate);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_triple_gate_sat_for_sound_reserve_transition() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        configure_solver(&ctx, &solver);

        let pair = Address::from([0x22; 20]);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);
        machine.inject_balance_override(ATTACKER, BV::from_u64(&ctx, 15_000, 256));
        machine.manipulated_reserves.insert(
            pair,
            (BV::from_u64(&ctx, 1_100, 256), BV::from_u64(&ctx, 950, 256)),
        );
        let loan = BV::from_u64(&ctx, 100, 256);

        let mut baseline = HashMap::new();
        baseline.insert(
            pair,
            (
                BV::from_u64(&ctx, 1_000, 256),
                BV::from_u64(&ctx, 1_000, 256),
            ),
        );

        let checker = GlobalInvariantChecker::default();
        let gate =
            checker.build_constraints_with_baselines(&ctx, &machine, ATTACKER, &loan, &baseline);
        solver.assert(&gate);
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }
}
