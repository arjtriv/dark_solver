use dark_solver::protocols::uniswap_v3;
use dark_solver::symbolic::utils::math::val;
use z3::ast::Ast;
use z3::Config;
use z3::Context;

#[test]
fn test_uniswap_v3_swap_exact_input_zero_for_one() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    // Setup:
    // Liquidity = 10^18
    // Price = 1.0 (sqrtPriceX96 = 2^96)
    // AmountIn = 1000
    // Fee = 0

    let liquidity = val(&ctx, 1_000_000_000_000_000_000);
    let q96 = val(&ctx, 1).bvshl(&val(&ctx, 96));
    let sqrt_price = q96.clone();
    let amount_in = val(&ctx, 1000);

    let amount_out = uniswap_v3::get_amount_out(
        &ctx,
        &amount_in,
        &liquidity,
        &sqrt_price,
        true, // zero_for_one
        0,    // fee_pips
    );

    // Expected: 999 or 1000 depending on internal rounding (V3 uses specific rounding directions)
    // We allow either for the symbolic model as long as it's within 1 wei of ideal mathematical result.
    let expected_999 = val(&ctx, 999);
    let expected_1000 = val(&ctx, 1000);

    let is_999 = amount_out._eq(&expected_999);
    let is_1000 = amount_out._eq(&expected_1000);

    let solver = z3::Solver::new(&ctx);
    solver.assert(&z3::ast::Bool::or(&ctx, &[&is_999, &is_1000]));

    assert_eq!(
        solver.check(),
        z3::SatResult::Sat,
        "Amount out should be 999 or 1000"
    );
}

#[test]
fn test_uniswap_v3_swap_exact_input_one_for_zero() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);

    let liquidity = val(&ctx, 1_000_000_000_000_000_000);
    let q96 = val(&ctx, 1).bvshl(&val(&ctx, 96));
    let sqrt_price = q96.clone();
    let amount_in = val(&ctx, 1000);

    let amount_out = uniswap_v3::get_amount_out(
        &ctx,
        &amount_in,
        &liquidity,
        &sqrt_price,
        false, // one_for_zero
        0,
    );

    let expected = val(&ctx, 999);
    let solver = z3::Solver::new(&ctx);
    solver.assert(&amount_out._eq(&expected));

    assert_eq!(
        solver.check(),
        z3::SatResult::Sat,
        "Amount out should be 999"
    );
}
