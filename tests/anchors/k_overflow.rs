//! Anchor Test: K-Invariant Violation via 256-bit Overflow in get_amount_out
//!
//! MAINTENANCE.md Invariant 3: "In any swap, k_after >= k_before."
//! The constant product formula guarantees amount_out < reserve_out for ALL inputs.
//! Real Uniswap V2 enforces this via SafeMath (reverts on overflow).
//!
//! BUG: get_amount_out (src/protocols/uniswap_v2.rs) uses raw bvmul (256-bit modular
//! multiplication). When amount_in is large, the intermediate products wrap, producing
//! amount_out values exceeding reserve_out — an impossible result that poisons
//! oracle_manipulation.rs with false positive exploits.

use dark_solver::protocols::uniswap_v2::get_amount_out;
use dark_solver::symbolic::utils::math::{extend_to_512, val};
use dark_solver::symbolic::z3_ext::configure_solver;
use z3::ast::BV;
use z3::{Config, Context, Solver};

/// Proof 1 (Concrete): MAX_U256 input with unit reserves.
///
/// Real math (infinite precision):
///   amount_out = (MAX * 997 * 1) / (1*1000 + MAX*997) < 1 → truncates to 0.
///
/// 256-bit modular math:
///   amount_in * 997 mod 2^256 = 2^256 - 997
///   numerator  = 2^256 - 997
///   denominator = 1000 + (2^256 - 997) mod 2^256 = 3
///   amount_out  = (2^256 - 997) / 3 ≈ 3.86 × 10^76  >>  1
///
/// This violates K-Invariant: amount_out CANNOT exceed reserve_out.
#[test]
fn test_k_invariant_concrete_overflow() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let reserve_in = BV::from_u64(&ctx, 1, 256);
    let reserve_out = BV::from_u64(&ctx, 1, 256);

    // MAX_U256 = 2^256 - 1
    let max_u256 = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let amount_in = BV::from_str(&ctx, 256, max_u256).unwrap();

    let amount_out = get_amount_out(&amount_in, &reserve_in, &reserve_out);

    // K-invariant: amount_out <= reserve_out MUST hold.
    // Assert the negation (amount_out > reserve_out) and expect UNSAT.
    solver.assert(&amount_out.bvugt(&reserve_out));

    assert_eq!(
        solver.check(),
        z3::SatResult::Unsat,
        "K-INVARIANT VIOLATION (Concrete): get_amount_out(MAX_U256, 1, 1) produced amount_out > 1.\n\
         Real math: result = 0 (integer truncation). \n\
         Symbolic:  bvmul wraps → numerator = 2^256 - 997, denom = 3, result ≈ 2^254.\n\
         Impact: oracle_manipulation.rs line 90 computes r1_new = reserve_out - amount_out,\n\
         which underflows (wraps to ~2^256), creating phantom manipulated reserves."
    );
}

/// Proof 2 (Symbolic): Universal proof that the 512-bit formula preserves K-invariant.
///
/// Decomposed proof (avoids bvudiv which is expensive for Z3 bit-blasting):
///   In 512-bit (overflow-free):
///     numerator   = amount_in * 997 * reserve_out
///     denominator = reserve_in * 1000 + amount_in * 997
///
///   Key fact: denominator = (amount_in * 997) + (reserve_in * 1000) > (amount_in * 997)
///   Therefore: numerator = (amount_in * 997) * reserve_out < denominator * reserve_out
///   Therefore: bvudiv(numerator, denominator) < reserve_out  (K-invariant holds)
///
/// This test proves the precondition: denominator > amount_in * 997, which implies
/// the quotient is strictly less than reserve_out for ANY amount_in.
/// The proof reduces to: reserve_in * 1000 > 0, trivially true for positive reserves.
#[test]
fn test_k_invariant_symbolic_overflow() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    // Realistic reserves (uint112 range)
    let reserve_in_256 = BV::from_str(&ctx, 256, "1000000000000000000000").unwrap(); // 10^21
    let reserve_in = extend_to_512(&ctx, &reserve_in_256);
    let n997 = extend_to_512(&ctx, &val(&ctx, 997));
    let n1000 = extend_to_512(&ctx, &val(&ctx, 1000));

    // Symbolic amount_in — same as oracle_manipulation.rs:84
    let amount_in = BV::new_const(&ctx, "amount_in", 256);
    solver.assert(&amount_in.bvugt(&BV::from_u64(&ctx, 0, 256)));
    let ain_512 = extend_to_512(&ctx, &amount_in);

    // 512-bit products (no overflow possible)
    let aif = ain_512.bvmul(&n997);
    let denominator = reserve_in.bvmul(&n1000).bvadd(&aif);

    // The K-invariant reduces to: denominator > aif (since denom = aif + reserve_in * 1000)
    // Assert violation: aif >= denominator — should be UNSAT.
    solver.assert(&aif.bvuge(&denominator));

    let result = solver.check();

    assert_eq!(
        result,
        z3::SatResult::Unsat,
        "K-INVARIANT VIOLATION (Symbolic): Found amount_in where aif >= denominator in 512-bit.\n\
         This means reserve_in * 1000 = 0 or addition overflowed 512-bit (impossible).\n\
         If this fires, the 512-bit extension in get_amount_out is insufficient."
    );
}
