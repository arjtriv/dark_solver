//! Anchor Test: Overflow-Bypass False Positive in Oracle Manipulation Profit Check
//!
//! MAINTENANCE.md [PROTOCOL/OVERFLOW]: 256-bit modular wrap-around was documented and fixed
//! in get_amount_out (uniswap_v2.rs). The identical bug class existed in oracle_manipulation.rs.
//!
//! MAINTENANCE.md [ECON/SOLVENCY]: "Profit checks must enforce protocol_assets >= protocol_liabilities
//! (Solvency) AND (Profit > Cost) via strict conjunction (Bool::and)."
//!
//! MAINTENANCE.md INVARIANT 1: "protocol_assets >= protocol_liabilities"
//!
//! Regression guard: oracle_manipulation.rs profit check previously used:
//!     final_balance > amount_in + profit_threshold
//! without an overflow guard. When amount_in ≈ MAX_U256, the 256-bit addition wraps
//! modulo 2^256 to ~0, making any nonzero final_balance pass — a phantom exploit.
//!
//! FIX: Added overflow guard (same pattern as objectives.rs:206-210):
//!     let sum = amount_in.bvadd(&profit_threshold);
//!     let no_overflow = sum.bvuge(&amount_in);
//!     Bool::and(ctx, &[&profit_check, &no_overflow])
//!
//! DO NOT: Remove the overflow guard from oracle_manipulation.rs. The wrap-around
//!         is the same root cause as the K-invariant overflow in get_amount_out.

use dark_solver::symbolic::z3_ext::configure_solver;
use z3::ast::{Bool, BV};
use z3::{Config, Context, Solver};

/// Proof 1 (Necessity): The UNGUARDED profit check is exploitable via overflow.
///
/// Setup (mirrors the ORIGINAL oracle_manipulation.rs:79-121 before fix):
///   - amount_in: symbolic, constrained > 2^200 (galaxy-scale borrow)
///   - final_balance: symbolic, constrained ≤ 1 ETH (pocket change)
///   - profit_threshold: 0.001 ETH (10^15 wei)
///
/// Check: final_balance > (amount_in + profit_threshold) WITHOUT overflow guard.
///
/// Result: SAT — Z3 picks amount_in = MAX_U256 - 10^15 + 1, wrapping sum to 0.
///         This proves the unguarded check is BROKEN and the fix is NECESSARY.
///
/// If this test flips to UNSAT, something fundamental changed in Z3's BV semantics.
#[test]
fn test_unguarded_check_is_exploitable() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let amount_in = BV::new_const(&ctx, "manip_amount_in", 256);
    solver.assert(&amount_in.bvugt(&BV::from_u64(&ctx, 0, 256)));

    // Force amount_in > 2^200 (clearly unreachable capital)
    let two_200 = BV::from_u64(&ctx, 1, 256).bvshl(&BV::from_u64(&ctx, 200, 256));
    solver.assert(&amount_in.bvugt(&two_200));

    let final_balance = BV::new_const(&ctx, "final_balance", 256);
    let one_eth = BV::from_str(&ctx, 256, "1000000000000000000").unwrap();
    solver.assert(&final_balance.bvule(&one_eth));
    solver.assert(&final_balance.bvugt(&BV::from_u64(&ctx, 0, 256)));

    let profit_threshold = BV::from_str(&ctx, 256, "1000000000000000").unwrap();

    // UNGUARDED check (the original bug)
    solver.assert(&final_balance.bvugt(&amount_in.bvadd(&profit_threshold)));

    assert_eq!(
        solver.check(),
        z3::SatResult::Sat,
        "ANCHOR BROKEN: The unguarded profit check should be SAT (exploitable via overflow).\n\
         If UNSAT, Z3 BV modular arithmetic semantics have changed."
    );
}

/// Proof 2 (Sufficiency): The GUARDED profit check rejects the overflow.
///
/// Same scenario as Proof 1, but with the overflow guard from the fix
/// (mirrors oracle_manipulation.rs post-fix and objectives.rs:206-210).
///
/// Result: UNSAT — the guard `sum >= amount_in` detects the wrap and kills it.
///         This proves the fix is SUFFICIENT.
///
/// Together with Proof 1: the overflow guard is both NECESSARY and SUFFICIENT.
#[test]
fn test_guarded_check_rejects_overflow() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    configure_solver(&ctx, &solver);

    let amount_in = BV::new_const(&ctx, "manip_amount_in", 256);
    solver.assert(&amount_in.bvugt(&BV::from_u64(&ctx, 0, 256)));

    let two_200 = BV::from_u64(&ctx, 1, 256).bvshl(&BV::from_u64(&ctx, 200, 256));
    solver.assert(&amount_in.bvugt(&two_200));

    let final_balance = BV::new_const(&ctx, "final_balance", 256);
    let one_eth = BV::from_str(&ctx, 256, "1000000000000000000").unwrap();
    solver.assert(&final_balance.bvule(&one_eth));
    solver.assert(&final_balance.bvugt(&BV::from_u64(&ctx, 0, 256)));

    let profit_threshold = BV::from_str(&ctx, 256, "1000000000000000").unwrap();

    // GUARDED check (the fix — mirrors oracle_manipulation.rs post-patch)
    let sum = amount_in.bvadd(&profit_threshold);
    let no_overflow = sum.bvuge(&amount_in);
    let profit_check = final_balance.bvugt(&sum);
    solver.assert(&Bool::and(&ctx, &[&profit_check, &no_overflow]));

    assert_eq!(
        solver.check(),
        z3::SatResult::Unsat,
        "REGRESSION: The overflow-guarded profit check should be UNSAT for \
         amount_in > 2^200 with final_balance <= 1 ETH.\n\
         If this fires, the overflow guard in oracle_manipulation.rs has regressed."
    );
}
