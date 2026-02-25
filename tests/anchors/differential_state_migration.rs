//! Anchor: Differential state migration must preserve multi-block spacing under head drift.

use alloy::primitives::{Address, Bytes, U256};
use dark_solver::executor::jit_migration::build_differential_migration_candidates;
use dark_solver::solver::objectives::{ExploitParams, ExploitStep};

fn dummy_params(offsets: Option<Vec<u64>>) -> ExploitParams {
    ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: vec![
            ExploitStep {
                target: Address::ZERO,
                call_data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
                execute_if: None,
            },
            ExploitStep {
                target: Address::ZERO,
                call_data: Bytes::from_static(&[0xca, 0xfe, 0xba, 0xbe]),
                execute_if: None,
            },
        ],
        expected_profit: Some(U256::from(1u64)),
        block_offsets: offsets,
    }
}

#[test]
fn anchor_differential_state_migration_preserves_spacing() {
    // Regression guard: large solve->head deltas must not force [0,1] into [0,0] only.
    let params = dummy_params(Some(vec![0, 1]));
    let candidates = build_differential_migration_candidates(&params, 100, 103, 0);
    let offsets = candidates
        .iter()
        .filter_map(|p| p.block_offsets.clone())
        .collect::<Vec<_>>();
    assert!(offsets.contains(&vec![0, 1]));
}
