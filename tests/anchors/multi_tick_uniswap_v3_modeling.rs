use dark_solver::protocols::uniswap_v3;
use dark_solver::symbolic::utils::math::val;
use z3::ast::Ast;
use z3::{Config, Context, Solver};

#[test]
fn test_multi_tick_uniswap_v3_modeling_crosses_and_updates_liquidity() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // Deterministic multi-tick example (fee=0) where crossing the first tick increases liquidity
    // before the second tick computation. All sqrt prices are multiples of Q96 so the math is exact.
    //
    // Direction: one_for_zero (sqrt increases).
    // Tick 1: sqrt 1Q -> 2Q with L=12, liquidityNet=+4 (so L becomes 16)
    // Tick 2: sqrt 2Q -> 4Q with L=16, liquidityNet=+0 (so L stays 16)
    //
    // Required input to reach a target in this direction: amount1 = L * (sqrtT - sqrtP) / Q96
    // So total exact input = 12*1 + 16*2 = 44.
    // Expected output token0 across both steps:
    // - step1: floor(12*(2-1)/(1*2)) = 6
    // - step2: floor(16*(4-2)/(2*4)) = 4
    // total = 10.
    let q96 = val(&ctx, 1).bvshl(&val(&ctx, 96));
    let sqrt_1q = q96.clone();
    let sqrt_2q = q96.bvshl(&val(&ctx, 1));
    let sqrt_4q = q96.bvshl(&val(&ctx, 2));

    let liquidity = val(&ctx, 12);
    let amount_in = val(&ctx, 44);

    let targets = vec![sqrt_2q.clone(), sqrt_4q.clone()];
    let nets = vec![val(&ctx, 4), val(&ctx, 0)];

    let res = uniswap_v3::swap_exact_in_multi_tick(
        &ctx, &amount_in, &liquidity, &sqrt_1q, false, // one_for_zero
        0,     // fee_pips
        &targets, &nets,
    );

    solver.assert(&res.ok);
    solver.assert(&res.sqrt_price_x96._eq(&sqrt_4q));
    solver.assert(&res.liquidity._eq(&val(&ctx, 16)));
    solver.assert(&res.amount_remaining._eq(&val(&ctx, 0)));
    solver.assert(&res.amount_out._eq(&val(&ctx, 10)));

    assert_eq!(solver.check(), z3::SatResult::Sat);
}
