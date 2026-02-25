use dark_solver::solver::liquidity::{
    slippage_solver_constraint_enabled, verify_exact_input_single_liquidity_blocking,
};
use dark_solver::solver::objectives::ExploitParams;
use revm::primitives::{Address, U256};

#[test]
fn slippage_solve_phase_gate_anchor() {
    let params = ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: Vec::new(),
        expected_profit: None,
        block_offsets: None,
    };
    let out = verify_exact_input_single_liquidity_blocking(8453, "http://127.0.0.1:1", &params)
        .expect("empty exploit params should skip slippage oracle call");
    assert!(out.is_none());

    // Anchor presence: solve-phase gate toggle is callable.
    let _enabled = slippage_solver_constraint_enabled();
}
