//! Anchor Test: Atomic Invariant Anchors wrap the final step calldata deterministically.

use alloy::primitives::{Address, Bytes, U256};
use dark_solver::executor::invariant_anchors::{
    decode_anchor_call_data, maybe_wrap_with_atomic_invariant_anchor,
};
use dark_solver::solver::objectives::{ExploitParams, ExploitStep};

fn restore_env(key: &str, previous: Option<String>) {
    if let Some(v) = previous {
        std::env::set_var(key, v);
    } else {
        std::env::remove_var(key);
    }
}

#[test]
fn test_atomic_invariant_anchor_wraps_last_step_when_configured() {
    let old_addr = std::env::var("INVARIANT_ANCHOR_ADDRESS").ok();
    let old_enabled = std::env::var("INVARIANT_ANCHOR_ENABLED").ok();
    let old_delta = std::env::var("INVARIANT_ANCHOR_MIN_DELTA").ok();

    let anchor = Address::new([0x99; 20]);
    std::env::set_var("INVARIANT_ANCHOR_ADDRESS", format!("{anchor:#x}"));
    std::env::set_var("INVARIANT_ANCHOR_ENABLED", "true");
    std::env::set_var("INVARIANT_ANCHOR_MIN_DELTA", "7");

    let step_a_target = Address::new([0x11; 20]);
    let step_b_target = Address::new([0x22; 20]);
    let step_b_data = Bytes::from(vec![0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02]);

    let params = ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::new([0x55; 20]),
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: vec![
            ExploitStep {
                target: step_a_target,
                call_data: Bytes::from(vec![0x01]),
                execute_if: None,
            },
            ExploitStep {
                target: step_b_target,
                call_data: step_b_data.clone(),
                execute_if: None,
            },
        ],
        expected_profit: None,
        block_offsets: None,
    };

    let wrapped = maybe_wrap_with_atomic_invariant_anchor(params, 1);

    restore_env("INVARIANT_ANCHOR_ADDRESS", old_addr);
    restore_env("INVARIANT_ANCHOR_ENABLED", old_enabled);
    restore_env("INVARIANT_ANCHOR_MIN_DELTA", old_delta);

    assert_eq!(wrapped.steps.len(), 2);
    assert_eq!(wrapped.steps[0].target, step_a_target);

    let last = &wrapped.steps[1];
    assert_eq!(last.target, anchor);
    let (profit_token, min_delta, inner_target, inner_data) =
        decode_anchor_call_data(&last.call_data).expect("decode anchor call");
    assert_eq!(profit_token, Address::new([0x55; 20]));
    assert_eq!(min_delta, U256::from(7u64));
    assert_eq!(inner_target, step_b_target);
    assert_eq!(inner_data, step_b_data);
}
