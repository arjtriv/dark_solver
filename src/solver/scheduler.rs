use crate::solver::objectives::{ExploitParams, ExploitStep};
use revm::primitives::U256;

const MAX_MERGED_STEPS: usize = 16;

fn offsets_are_flat(params: &ExploitParams) -> bool {
    match params.block_offsets.as_ref() {
        None => true,
        Some(offsets) => offsets.iter().all(|offset| *offset == 0),
    }
}

fn params_are_mergeable(params: &ExploitParams) -> bool {
    params.flash_loan_amount.is_zero()
        && params.flash_loan_legs.is_empty()
        && params.steps.iter().all(|step| step.execute_if.is_none())
        && offsets_are_flat(params)
}

fn merge_expected_profit(a: Option<U256>, b: Option<U256>) -> Option<U256> {
    Some(
        a.unwrap_or(U256::ZERO)
            .saturating_add(b.unwrap_or(U256::ZERO)),
    )
}

fn merge_steps(base: &[ExploitStep], extra: &[ExploitStep]) -> Vec<ExploitStep> {
    let mut out = Vec::with_capacity(base.len().saturating_add(extra.len()));
    out.extend_from_slice(base);
    out.extend_from_slice(extra);
    out
}

/// Greedy same-block scheduler:
/// merges orthogonal findings into one execution plan to avoid nonce races.
/// This is intentionally conservative: merge only flat, no-flash-loan, unconditional step plans.
pub fn greedy_schedule_findings(
    findings: Vec<(String, ExploitParams)>,
) -> Vec<(String, ExploitParams)> {
    let mut merged: Option<(String, ExploitParams)> = None;
    let mut passthrough = Vec::new();

    for (name, params) in findings {
        if !params_are_mergeable(&params) {
            passthrough.push((name, params));
            continue;
        }
        if let Some((merged_name, merged_params)) = merged.as_mut() {
            let merged_steps_len = merged_params.steps.len();
            let next_steps_len = params.steps.len();
            let next_total = merged_steps_len.saturating_add(next_steps_len);
            if next_total > MAX_MERGED_STEPS {
                passthrough.push((name, params));
                continue;
            }
            merged_params.steps = merge_steps(&merged_params.steps, &params.steps);
            merged_params.block_offsets = Some(vec![0; merged_params.steps.len()]);
            merged_params.expected_profit =
                merge_expected_profit(merged_params.expected_profit, params.expected_profit);
            *merged_name = format!("Greedy Scheduler Merge + {}", name);
            continue;
        }
        merged = Some((name, params));
    }

    if let Some(item) = merged {
        let mut out = vec![item];
        out.extend(passthrough);
        out
    } else {
        passthrough
    }
}

#[cfg(test)]
mod tests {
    use super::greedy_schedule_findings;
    use crate::solver::objectives::{ExploitParams, ExploitStep};
    use alloy::primitives::{Address, Bytes};
    use revm::primitives::U256;

    fn one_step_params(target: Address, selector: [u8; 4], profit: u64) -> ExploitParams {
        ExploitParams {
            flash_loan_amount: U256::ZERO,
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::new(),
            steps: vec![ExploitStep {
                target,
                call_data: Bytes::copy_from_slice(&selector),
                execute_if: None,
            }],
            expected_profit: Some(U256::from(profit)),
            block_offsets: None,
        }
    }

    #[test]
    fn test_greedy_scheduler_merges_simple_findings() {
        let target = Address::repeat_byte(0x11);
        let findings = vec![
            ("A".to_string(), one_step_params(target, [1, 2, 3, 4], 5)),
            ("B".to_string(), one_step_params(target, [5, 6, 7, 8], 7)),
        ];
        let out = greedy_schedule_findings(findings);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1.steps.len(), 2);
        assert_eq!(
            out[0].1.expected_profit.unwrap_or(U256::ZERO),
            U256::from(12u64)
        );
        assert!(out[0].0.contains("Greedy Scheduler Merge"));
    }
}
