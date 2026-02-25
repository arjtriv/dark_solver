use dark_solver::solver::objectives::is_profitable;
use dark_solver::symbolic::state::SymbolicMachine;
use revm::primitives::Address;
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[test]
fn test_phantom_liquidity_hallucination() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    // 1. Initial State
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    let attacker = Address::repeat_byte(0xAA);
    let target_contract = Address::repeat_byte(0xBB);
    let token = Address::repeat_byte(0xCC);

    // ETH Setup: Attacker is solvent
    let flash_loan_amount = BV::from_u64(&ctx, 0, 256);
    let total_cost = BV::from_u64(&ctx, 0, 256);
    machine.inject_balance_override(attacker, flash_loan_amount.clone());

    // Token Setup: Attacker starts with 0 tokens.
    let initial_attacker_tokens = BV::from_u64(&ctx, 0, 256);
    machine
        .token_balances
        .insert((token, attacker), initial_attacker_tokens.clone());

    // 2. The Transfer Model (Internal logic of calls.rs:188-213)
    // We simulate what happens when transfer(attacker, 100) is called by target_contract.
    let amount = BV::from_u64(&ctx, 100, 256);

    // from_bal is retrieved for (token, target_contract)
    // Sound behavior: missing balances default to zero, not unconstrained symbolic liquidity.
    let from_key = (token, target_contract);
    let from_bal = machine
        .token_balances
        .entry(from_key)
        .or_insert(BV::from_u64(&ctx, 0, 256));

    let has_balance = from_bal.bvuge(&amount);

    // UPDATE ATTACKER BALANCE: new_to = ITE(has_balance, to + amount, to)
    let to_key = (token, attacker);
    let to_bal = machine
        .token_balances
        .entry(to_key)
        .or_insert(BV::from_u64(&ctx, 0, 256))
        .clone();
    let new_to = has_balance.ite(&to_bal.bvadd(&amount), &to_bal);
    machine.token_balances.insert(to_key, new_to);

    // 3. Profit Check
    let initial_token_vars = vec![(token, initial_attacker_tokens)];
    let profitable = is_profitable(
        &ctx,
        &machine,
        attacker,
        &total_cost,
        &flash_loan_amount,
        &initial_token_vars,
    );

    solver.assert(&profitable);

    // 4. Assertion
    // If the solver says SAT, it means it "hallucinated" that target_contract had tokens.
    // In a sound engine, this should be UNSAT because target_contract was never given tokens.
    // The engine MUST ground all initial balances in concrete state or default to zero.
    let result = solver.check();

    assert_eq!(
        result,
        z3::SatResult::Unsat,
        "Solver inferred initial token liquidity for an uninitialized account, producing a false-positive path."
    );
}

#[test]
fn test_explicit_balance_injection_strategy_is_modeled() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    let attacker = Address::repeat_byte(0xAA);
    let target_contract = Address::repeat_byte(0xBB);
    let token = Address::repeat_byte(0xCC);

    let flash_loan_amount = BV::from_u64(&ctx, 0, 256);
    let total_cost = BV::from_u64(&ctx, 0, 256);
    machine.inject_balance_override(attacker, flash_loan_amount.clone());

    let initial_attacker_tokens = BV::from_u64(&ctx, 0, 256);
    machine
        .token_balances
        .insert((token, attacker), initial_attacker_tokens.clone());

    // Controlled balance injection: target starts with bounded symbolic liquidity.
    let amount = BV::from_u64(&ctx, 100, 256);
    let injected = BV::new_const(&ctx, "injected_contract_tokens", 256);
    solver.assert(&injected.bvugt(&BV::from_u64(&ctx, 0, 256)));
    solver.assert(&injected.bvule(&BV::from_u64(&ctx, 10_000, 256)));

    let from_key = (token, target_contract);
    let from_bal = machine
        .token_balances
        .entry(from_key)
        .or_insert(injected.clone());
    let has_balance = from_bal.bvuge(&amount);

    let to_key = (token, attacker);
    let to_bal = machine
        .token_balances
        .entry(to_key)
        .or_insert(BV::from_u64(&ctx, 0, 256))
        .clone();
    let new_to = has_balance.ite(&to_bal.bvadd(&amount), &to_bal);
    machine.token_balances.insert(to_key, new_to);

    let initial_token_vars = vec![(token, initial_attacker_tokens)];
    let profitable = is_profitable(
        &ctx,
        &machine,
        attacker,
        &total_cost,
        &flash_loan_amount,
        &initial_token_vars,
    );
    solver.assert(&profitable);

    assert_eq!(
        solver.check(),
        z3::SatResult::Sat,
        "Balance-injection strategy should remain expressible when explicitly modeled."
    );
}
