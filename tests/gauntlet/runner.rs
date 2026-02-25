use dark_solver::protocols::erc4626::assets_per_share_non_decreasing;
use dark_solver::protocols::lending::isolation_mode_borrow_allowed;
use dark_solver::protocols::uniswap_v2::get_amount_out;
use dark_solver::symbolic::z3_ext::configure_solver;
use z3::ast::{Bool, BV};
use z3::{Config, Context, SatResult, Solver};

use crate::catalog::{Expectation, GauntletCase, Scenario};

fn parse_u256<'ctx>(ctx: &'ctx Context, value: &str) -> Result<BV<'ctx>, String> {
    BV::from_str(ctx, 256, value)
        .ok_or_else(|| format!("invalid u256 literal for gauntlet case: {}", value))
}

fn expected_sat_result(expected: Expectation) -> SatResult {
    match expected {
        Expectation::Sat => SatResult::Sat,
        Expectation::Unsat => SatResult::Unsat,
    }
}

fn assert_expected(case: &GauntletCase, actual: SatResult) -> Result<(), String> {
    let expected = expected_sat_result(case.expected);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "expected {:?}, got {:?} for primitive {}",
            expected, actual, case.primitive
        ))
    }
}

pub fn run_case(case: &GauntletCase) -> Result<(), String> {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    match &case.scenario {
        Scenario::UniV2KInvariant {
            amount_in,
            reserve_in,
            reserve_out,
        } => {
            let amount_in = parse_u256(&ctx, amount_in)?;
            let reserve_in = BV::from_u64(&ctx, *reserve_in, 256);
            let reserve_out = BV::from_u64(&ctx, *reserve_out, 256);
            let amount_out = get_amount_out(&amount_in, &reserve_in, &reserve_out);
            solver.assert(&amount_out.bvugt(&reserve_out));
            assert_expected(case, solver.check())
        }
        Scenario::ProfitOverflowGuard {
            min_amount_bits,
            max_final_balance,
            profit_threshold,
        } => {
            let amount_in = BV::new_const(&ctx, format!("gauntlet_amount_in_{}", case.id), 256);
            solver.assert(&amount_in.bvugt(&BV::from_u64(&ctx, 0, 256)));

            let min_amount = BV::from_u64(&ctx, 1, 256).bvshl(&BV::from_u64(
                &ctx,
                u64::from(*min_amount_bits),
                256,
            ));
            solver.assert(&amount_in.bvugt(&min_amount));

            let final_balance =
                BV::new_const(&ctx, format!("gauntlet_final_balance_{}", case.id), 256);
            solver.assert(&final_balance.bvugt(&BV::from_u64(&ctx, 0, 256)));
            solver.assert(&final_balance.bvule(&BV::from_u64(&ctx, *max_final_balance, 256)));

            let threshold = BV::from_u64(&ctx, *profit_threshold, 256);
            let sum = amount_in.bvadd(&threshold);
            let no_overflow = sum.bvuge(&amount_in);
            let profit_check = final_balance.bvugt(&sum);
            solver.assert(&Bool::and(&ctx, &[&profit_check, &no_overflow]));

            assert_expected(case, solver.check())
        }
        Scenario::ReserveOverflowGuard { reserve } => {
            let reserve = BV::from_u64(&ctx, *reserve, 256);
            let amount_in =
                BV::new_const(&ctx, format!("gauntlet_reserve_addend_{}", case.id), 256);
            solver.assert(&amount_in.bvugt(&BV::from_u64(&ctx, 0, 256)));
            let new_reserve = reserve.bvadd(&amount_in);

            // Guarded update must never wrap below prior reserve.
            solver.assert(&new_reserve.bvuge(&reserve));
            solver.assert(&new_reserve.bvult(&reserve));

            assert_expected(case, solver.check())
        }
        Scenario::Erc4626ShareRatio {
            initial_assets,
            initial_supply,
            final_assets,
            final_supply,
        } => {
            let inv = assets_per_share_non_decreasing(
                &ctx,
                &BV::from_u64(&ctx, *initial_assets, 256),
                &BV::from_u64(&ctx, *initial_supply, 256),
                &BV::from_u64(&ctx, *final_assets, 256),
                &BV::from_u64(&ctx, *final_supply, 256),
            );
            solver.assert(&inv.not());
            assert_expected(case, solver.check())
        }
        Scenario::IsolationModeBorrow {
            isolation_enabled,
            asset_borrowable,
            total_isolation_debt,
            borrow_amount,
            debt_ceiling,
        } => {
            let allowed = isolation_mode_borrow_allowed(
                &ctx,
                &Bool::from_bool(&ctx, *isolation_enabled),
                &Bool::from_bool(&ctx, *asset_borrowable),
                &BV::from_u64(&ctx, *total_isolation_debt, 256),
                &BV::from_u64(&ctx, *borrow_amount, 256),
                &BV::from_u64(&ctx, *debt_ceiling, 256),
            );
            solver.assert(&allowed);
            assert_expected(case, solver.check())
        }
    }
}
