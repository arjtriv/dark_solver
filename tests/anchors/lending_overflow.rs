//! Anchor Test: 256-bit Overflow in Lending Protocol Model (get_redemption_amount)
//!
//! MAINTENANCE.md Constraint [PROTOCOL/OVERFLOW] (verbatim):
//!   "Any future protocol formula model involving multiplication of 2+ symbolic terms
//!    MUST use extend_to_512 to prevent modular wrap-around."
//!
//! BUG: get_redemption_amount (src/protocols/lending.rs:16) computes:
//!     safe_div(&c_token_amount.bvmul(exchange_rate), &scaling_factor)
//! using raw 256-bit bvmul. This is the identical bug class as the [SOLVED][PROTOCOL/OVERFLOW]
//! K-invariant violation in uniswap_v2.rs. When c_token_amount is large, the intermediate
//! product wraps modulo 2^256, producing a mathematically incorrect redemption amount.
//!
//! The same bug exists in get_mint_amount (lending.rs:27):
//!     safe_div(&underlying_amount.bvmul(&scaling_factor), exchange_rate)
//!
//! Impact: Any solver objective that uses these functions builds an incorrect constraint
//! model for large symbolic inputs. The overflow can produce false negatives (solver misses
//! real lending exploits) or false positives (phantom profits) depending on how the
//! function output feeds into the profit check.
//!
//! Fix: Replace raw bvmul with extend_to_512-based multiplication,
//!      matching the pattern in uniswap_v2.rs::get_amount_out.

use dark_solver::protocols::lending::get_redemption_amount;
use dark_solver::symbolic::utils::math::wad;
use dark_solver::symbolic::z3_ext::configure_solver;
use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};

/// Proof 1 (Identity Violation): get_redemption_amount(X, WAD) should equal X.
///
/// When exchange_rate = WAD (1.0), the function is the identity:
///   Correct: floor(X * WAD / WAD) = X
///
/// With 256-bit overflow (X = MAX_U256):
///   MAX_U256 * WAD = (2^256 - 1) * 10^18
///                  = 2^256 * 10^18 - 10^18
///   mod 2^256      = -10^18 mod 2^256
///                  = 2^256 - 10^18
///   floor((2^256 - 10^18) / 10^18) = floor(2^256/10^18) - 1 ≈ 1.16 × 10^59
///
/// But MAX_U256 ≈ 1.16 × 10^77.  Off by a factor of 10^18.
///
/// This test asserts the identity property holds. It FAILS because the overflow
/// destroys the most basic mathematical property of the function.
#[test]
fn test_lending_identity_violation() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    // X = MAX_U256 = 2^256 - 1
    let max_u256_str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let c_token_amount = BV::from_str(&ctx, 256, max_u256_str).unwrap();

    // E = WAD (exchange rate 1.0: identity transformation)
    let exchange_rate = wad(&ctx);

    // Buggy result (256-bit bvmul)
    let buggy_result = get_redemption_amount(&c_token_amount, &exchange_rate);

    // Identity property: get_redemption_amount(X, WAD) == X
    // Assert violation: buggy != X. Expect UNSAT (they agree).
    solver.assert(&buggy_result._eq(&c_token_amount).not());

    assert_eq!(
        solver.check(),
        z3::SatResult::Unsat,
        "IDENTITY VIOLATION: get_redemption_amount(MAX_U256, WAD) != MAX_U256.\n\
         With exchange_rate = WAD, the function should be the identity: floor(X * WAD / WAD) = X.\n\
         But 256-bit bvmul wraps: MAX_U256 * WAD mod 2^256 = 2^256 - WAD,\n\
         giving floor((2^256 - WAD) / WAD) ≈ 10^59 instead of MAX_U256 ≈ 10^77.\n\
         Root cause: lending.rs:16 uses c_token_amount.bvmul(exchange_rate) in 256-bit.\n\
         Identical bug class to MAINTENANCE.md [PROTOCOL/OVERFLOW] in uniswap_v2.rs.\n\
         Fix: Use extend_to_512 for intermediate multiplication, same as get_amount_out."
    );
}

/// Proof 2 (Realistic Inputs): 2^200 cTokens at 2x exchange rate.
///
/// c_token_amount = 2^200 (~1.6 × 10^60 — plausible in wei-denominated flash loan)
/// exchange_rate  = 2 * WAD (healthy lending market: 1 cToken redeems 2 underlying)
///
/// Correct (infinite precision):
///   redemption = floor(2^200 * 2 × 10^18 / 10^18) = 2^200 * 2 = 2^201
///
/// Buggy (256-bit wrap):
///   2^200 * 2 × 10^18 = 2^201 * 10^18
///   log2(2^201 * 10^18) = 201 + 59.79 = 260.79 > 256  →  OVERFLOW
///   Wrapped product mod 2^256 ≠ true product
///   floor(wrapped / WAD) ≠ 2^201
///
/// This test asserts the function produces 2^201. It FAILS because the
/// intermediate product overflows 256 bits.
#[test]
fn test_lending_realistic_overflow() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    // c_token_amount = 2^200
    let c_token_amount = BV::from_u64(&ctx, 1, 256).bvshl(&BV::from_u64(&ctx, 200, 256));

    // exchange_rate = 2 * WAD = 2e18
    let exchange_rate = BV::from_str(&ctx, 256, "2000000000000000000").unwrap();

    // Buggy result (256-bit bvmul)
    let buggy_result = get_redemption_amount(&c_token_amount, &exchange_rate);

    // Correct result: 2^201
    let correct_result = BV::from_u64(&ctx, 1, 256).bvshl(&BV::from_u64(&ctx, 201, 256));

    // Assert: buggy == correct. Expect UNSAT for the negation (they agree).
    solver.assert(&buggy_result._eq(&correct_result).not());

    assert_eq!(
        solver.check(),
        z3::SatResult::Unsat,
        "LENDING OVERFLOW: get_redemption_amount(2^200, 2*WAD) != 2^201.\n\
         The intermediate product 2^200 * 2e18 ≈ 2^261 overflows 256-bit arithmetic.\n\
         This is the identical bug class as [PROTOCOL/OVERFLOW] in uniswap_v2.rs.\n\
         Fix: Replace c_token_amount.bvmul(exchange_rate) with:\n\
           let ct_512 = extend_to_512(ctx, c_token_amount);\n\
           let er_512 = extend_to_512(ctx, exchange_rate);\n\
           safe_div(&ct_512.bvmul(&er_512), &extend_to_512(ctx, &wad)).extract(255, 0)"
    );
}
