use dark_solver::protocols::uniswap_v3::{
    next_initialized_tick_within_one_word, symbolic_tick_bitmap,
};
use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};

#[test]
fn test_uniswap_v3_bitmap_anchor_lte_jump() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let base = symbolic_tick_bitmap(&ctx, "anchor_tick_bitmap_lte");
    let word_val = BV::from_u64(&ctx, (1u64 << 3) | (1u64 << 9), 256);
    let bitmap = base.store(&BV::from_u64(&ctx, 0, 256), &word_val);

    let current_tick = BV::from_u64(&ctx, 8, 256);
    let (next_tick, found) =
        next_initialized_tick_within_one_word(&ctx, &bitmap, &current_tick, 1, true);

    solver.assert(&found);
    solver.assert(&next_tick._eq(&BV::from_u64(&ctx, 3, 256)));
    assert_eq!(solver.check(), z3::SatResult::Sat);
}

#[test]
fn test_uniswap_v3_bitmap_anchor_gt_jump() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let base = symbolic_tick_bitmap(&ctx, "anchor_tick_bitmap_gt");
    let word_val = BV::from_u64(&ctx, (1u64 << 3) | (1u64 << 9), 256);
    let bitmap = base.store(&BV::from_u64(&ctx, 0, 256), &word_val);

    let current_tick = BV::from_u64(&ctx, 8, 256);
    let (next_tick, found) =
        next_initialized_tick_within_one_word(&ctx, &bitmap, &current_tick, 1, false);

    solver.assert(&found);
    solver.assert(&next_tick._eq(&BV::from_u64(&ctx, 9, 256)));
    assert_eq!(solver.check(), z3::SatResult::Sat);
}
