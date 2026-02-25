//! Anchor: per-block interest/index accrual helpers for Aave/Compound must be deterministic and exact.

use dark_solver::protocols::lending::{
    aave_index_compound_after_blocks_wad, apply_index_ratio,
    compound_borrow_index_simple_after_blocks_wad,
};
use dark_solver::symbolic::z3_ext::{bv_from_u256, u256_from_bv};
use revm::primitives::U256;
use z3::ast::Ast;
use z3::{Config, Context, Solver};

fn wad_u256() -> U256 {
    U256::from(10u64).pow(U256::from(18u64))
}

#[test]
fn accrued_interest_modeling_compound_simple_interest_matches_expected() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let wad = wad_u256();
    let borrow_index_before = bv_from_u256(&ctx, wad); // 1.0
    let one_pct = bv_from_u256(&ctx, wad / U256::from(100u64)); // 0.01
    let borrow_index_after =
        compound_borrow_index_simple_after_blocks_wad(&ctx, &borrow_index_before, &one_pct, 10);

    // 1.0 * (1 + 0.01*10) = 1.1
    let expected = bv_from_u256(&ctx, (wad * U256::from(110u64)) / U256::from(100u64));
    solver.assert(&borrow_index_after._eq(&expected));
    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn accrued_interest_modeling_aave_compounding_matches_expected() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let wad = wad_u256();
    let index_before = bv_from_u256(&ctx, wad); // 1.0
    let one_pct = bv_from_u256(&ctx, wad / U256::from(100u64)); // 0.01
    let index_after = aave_index_compound_after_blocks_wad(&ctx, &index_before, &one_pct, 2);

    // 1.0 * (1.01^2) = 1.0201
    let expected = bv_from_u256(&ctx, (wad * U256::from(10201u64)) / U256::from(10_000u64));
    solver.assert(&index_after._eq(&expected));
    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn accrued_interest_modeling_apply_index_ratio_scales_balances() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let wad = wad_u256();
    let index_before = bv_from_u256(&ctx, wad); // 1.0
    let index_after = bv_from_u256(&ctx, (wad * U256::from(11u64)) / U256::from(10u64)); // 1.1
    let balance_before = bv_from_u256(&ctx, U256::from(1000u64));
    let balance_after = apply_index_ratio(&ctx, &balance_before, &index_before, &index_after);

    solver.assert(&balance_after._eq(&bv_from_u256(&ctx, U256::from(1100u64))));
    assert_eq!(solver.check(), z3::SatResult::Sat);

    // Sanity: this stays concrete and decodable.
    assert_eq!(u256_from_bv(&balance_after), Some(U256::from(1100u64)));
}
