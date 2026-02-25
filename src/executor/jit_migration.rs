//! Differential JIT migration helpers.
//!
//! Background (deep) findings can arrive multiple blocks after the solve head.
//! "Differential state migration" means: keep the exploit's *shape* (step ordering
//! and inter-step block deltas) and rebase the schedule toward the latest head,
//! then accept only candidates that pass a concrete latest-head replay.

use crate::solver::objectives::ExploitParams;

fn normalize_offsets_non_decreasing(offsets: &mut [u64]) {
    let mut prev = 0u64;
    for value in offsets {
        if *value < prev {
            *value = prev;
        }
        prev = *value;
    }
}

fn default_step_offsets(steps_len: usize) -> Option<Vec<u64>> {
    if steps_len <= 1 {
        return None;
    }
    Some((0..steps_len as u64).collect())
}

fn extract_offsets_or_default(params: &ExploitParams) -> Option<Vec<u64>> {
    let steps_len = params.steps.len();
    match params.block_offsets.clone() {
        Some(offsets) if offsets.len() == steps_len => Some(offsets),
        _ => default_step_offsets(steps_len),
    }
}

fn offsets_to_deltas(offsets: &[u64]) -> Vec<u64> {
    let mut deltas = Vec::with_capacity(offsets.len().saturating_sub(1));
    for window in offsets.windows(2) {
        deltas.push(window[1].saturating_sub(window[0]));
    }
    deltas
}

fn rebuild_offsets_from_start_and_deltas(start: u64, deltas: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(deltas.len().saturating_add(1));
    out.push(start);
    for delta in deltas {
        let prev = *out.last().unwrap_or(&0);
        out.push(prev.saturating_add(*delta));
    }
    out
}

fn with_offsets(params: &ExploitParams, offsets: Vec<u64>) -> ExploitParams {
    let mut tuned = params.clone();
    tuned.block_offsets = Some(offsets);
    tuned
}

fn compress_offsets_for_latest_head(offsets: &[u64], solve_delta_blocks: u64) -> Vec<u64> {
    let mut out = offsets
        .iter()
        .map(|value| value.saturating_sub(solve_delta_blocks))
        .collect::<Vec<_>>();
    normalize_offsets_non_decreasing(&mut out);
    out
}

/// Build bounded JIT migration candidates for a background finding.
///
/// Candidates are ordered from "least invasive" to "more invasive".
/// The caller should accept only candidates that pass a concrete replay at `latest_head`.
pub fn build_differential_migration_candidates(
    params: &ExploitParams,
    solve_target_block: u64,
    latest_head: u64,
    max_offset_shift: u64,
) -> Vec<ExploitParams> {
    let solve_delta = latest_head.saturating_sub(solve_target_block);

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::<Vec<u64>>::new();

    let Some(mut offsets) = extract_offsets_or_default(params) else {
        return vec![params.clone()];
    };
    normalize_offsets_non_decreasing(&mut offsets);
    let deltas = offsets_to_deltas(&offsets);

    // Candidate family A: preserve inter-step deltas; rebase the starting offset toward latest head.
    let base_start = offsets
        .first()
        .copied()
        .unwrap_or(0)
        .saturating_sub(solve_delta);
    for shift in 0..=max_offset_shift {
        let start = base_start.saturating_add(shift);
        let mut candidate = rebuild_offsets_from_start_and_deltas(start, &deltas);
        normalize_offsets_non_decreasing(&mut candidate);
        if seen.insert(candidate.clone()) {
            out.push(with_offsets(params, candidate));
        }
    }

    // Candidate family B: compress offsets element-wise (may collapse spacing); useful for cases
    // where the exploit's multi-block structure is optional and earlier execution is required.
    let compressed = compress_offsets_for_latest_head(&offsets, solve_delta);
    for shift in 0..=max_offset_shift {
        let mut candidate = compressed
            .iter()
            .map(|value| value.saturating_add(shift))
            .collect::<Vec<_>>();
        normalize_offsets_non_decreasing(&mut candidate);
        if seen.insert(candidate.clone()) {
            out.push(with_offsets(params, candidate));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::objectives::ExploitStep;
    use alloy::primitives::{Address, Bytes, U256};

    fn dummy_params_with_offsets(offsets: Option<Vec<u64>>) -> ExploitParams {
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
    fn test_differential_migration_preserves_spacing_under_large_head_delta() {
        // Previously: element-wise saturating_sub would collapse [0,1] -> [0,0] when delta=3.
        let params = dummy_params_with_offsets(Some(vec![0, 1]));
        let candidates = build_differential_migration_candidates(&params, 100, 103, 0);
        let offsets = candidates
            .iter()
            .filter_map(|p| p.block_offsets.clone())
            .collect::<Vec<_>>();
        assert!(offsets.contains(&vec![0, 1]));
    }

    #[test]
    fn test_differential_migration_includes_compressed_candidate() {
        let params = dummy_params_with_offsets(Some(vec![0, 1]));
        let candidates = build_differential_migration_candidates(&params, 100, 103, 0);
        let offsets = candidates
            .iter()
            .filter_map(|p| p.block_offsets.clone())
            .collect::<Vec<_>>();
        assert!(offsets.contains(&vec![0, 0]));
    }
}
