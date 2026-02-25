use dark_solver::solver::objectives::is_profitable;
use dark_solver::symbolic::state::SymbolicMachine;
use revm::primitives::Address;
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[test]
fn test_phantom_profit_ignores_debt() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // 1. Setup Logic
    // We pass None for fork_url because we override balances manually
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    let attacker = Address::repeat_byte(0xAA);
    let token = Address::repeat_byte(0xCC);
    // 2. Symbolic Variables
    // Simulate a Flash Loan of 10,000 wei
    let flash_loan_amount = BV::from_u64(&ctx, 10_000, 256);
    let total_cost = BV::from_u64(&ctx, 0, 256); // Assume 0 gas for simplicity
                                                 // 3. Scenario: "Exit Scam" (Swap Borrowed ETH for Token, Don't Repay)
                                                 // Initial State: StandardScenario injects balance = Loan.
                                                 // Execution: We spend ALL the ETH to buy tokens.
                                                 // Final ETH Balance = 0.
    machine.inject_balance_override(attacker, BV::from_u64(&ctx, 0, 256));

    // Final Token Balance: 1 wei (We gained 1 unit of token).
    // Initial Token Balance: 0.
    let initial_token_bal = BV::from_u64(&ctx, 0, 256);
    let final_token_bal = BV::from_u64(&ctx, 1, 256);

    machine
        .token_balances
        .insert((token, attacker), final_token_bal);
    let initial_token_vars = vec![(token, initial_token_bal)];
    // 4. The Check
    solver.push();
    let profitable = is_profitable(
        &ctx,
        &machine,
        attacker,
        &total_cost,
        &flash_loan_amount,
        &initial_token_vars,
    );
    solver.assert(&profitable);

    // 5. Assertion: This SHOULD be Unsat
    // Logic: We borrowed 10,000 ETH, have 0 ETH left. We are insolvent (-10,000 ETH).
    // The fact that we have +1 Token does not fix the ETH insolvency (Flash Loan reverts).
    //
    // BUG: Current is_profitable uses `OR`, so (Insolvent_ETH OR Profitable_Token) => SAT.
    let result = solver.check();

    // The proof: The test FAILS if the solver says SAT (Current Behavior).
    assert_eq!(
        result,
        z3::SatResult::Unsat,
        "Solver marked an insolvent path as profitable; token gains should not bypass debt repayment constraints."
    );
}
