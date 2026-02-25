use dark_solver::solver::objectives::is_profitable;
use dark_solver::symbolic::state::SymbolicMachine;
use revm::primitives::Address;
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[test]
fn test_erc20_token_profit_detection() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let attacker = Address::new([0xAA; 20]);
    let token = Address::new([0x11; 20]);

    let flash_loan_amount = BV::from_u64(&ctx, 10, 256);
    let total_cost = BV::from_u64(&ctx, 0, 256);

    // Keep the attacker solvent and inject a token balance increase.
    machine
        .balance_overrides
        .insert(attacker, flash_loan_amount.clone());
    machine
        .token_balances
        .insert((token, attacker), BV::from_u64(&ctx, 101, 256));

    let initial_token_vars = vec![(token, BV::from_u64(&ctx, 100, 256))];
    let profitable = is_profitable(
        &ctx,
        &machine,
        attacker,
        &total_cost,
        &flash_loan_amount,
        &initial_token_vars,
    );

    solver.assert(&profitable);
    assert_eq!(solver.check(), z3::SatResult::Sat);
}
