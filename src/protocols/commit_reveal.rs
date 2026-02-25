use crate::symbolic::utils::math::{safe_rem, zero};
use revm::primitives::Bytes;
use z3::ast::{Ast, Bool, BV};
use z3::Context;

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_commit_reveal_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("commit(bytes32)"),
        selector("commitHash(bytes32)"),
        selector("reveal(uint256,bytes32)"),
        selector("reveal(bytes32,uint256)"),
        selector("claimPrize()"),
        selector("claim()"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

fn bytecode_contains_selector(bytecode: &Bytes, selector: [u8; 4]) -> bool {
    let bytes = bytecode.as_ref();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 && bytes[i + 1..i + 5] == selector {
            return true;
        }
    }
    false
}

pub fn has_commit_reveal_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_sha3 = bytes.contains(&0x20);
    let has_sstore = bytes.contains(&0x55);
    let has_sload = bytes.contains(&0x54);
    let has_mod = bytes.contains(&0x06);
    let has_commit_selector = bytecode_contains_selector(bytecode, selector("commit(bytes32)"))
        || bytecode_contains_selector(bytecode, selector("commitHash(bytes32)"));
    let has_reveal_selector =
        bytecode_contains_selector(bytecode, selector("reveal(uint256,bytes32)"))
            || bytecode_contains_selector(bytecode, selector("reveal(bytes32,uint256)"));
    has_sha3 && has_sstore && has_sload && has_mod && (has_commit_selector || has_reveal_selector)
}

pub fn hash_matches_preimage<'ctx>(
    ctx: &'ctx Context,
    stored_commit_hash: &BV<'ctx>,
    leaked_seed: &BV<'ctx>,
) -> Bool<'ctx> {
    let keccak = crate::symbolic::z3_ext::KeccakTheory::new(ctx);
    let computed = keccak.apply_symbolic(Some(vec![leaked_seed.clone()]));
    stored_commit_hash._eq(&computed)
}

pub fn reveal_outcome_wins<'ctx>(
    ctx: &'ctx Context,
    leaked_seed: &BV<'ctx>,
    timestamp_next: &BV<'ctx>,
    prevrandao: &BV<'ctx>,
    modulo: &BV<'ctx>,
    winning_value: &BV<'ctx>,
) -> Bool<'ctx> {
    let keccak = crate::symbolic::z3_ext::KeccakTheory::new(ctx);
    let random = keccak.apply_symbolic(Some(vec![
        leaked_seed.clone(),
        timestamp_next.clone(),
        prevrandao.clone(),
    ]));
    let modulo_positive = modulo.bvugt(&zero(ctx));
    let win_in_range = winning_value.bvult(modulo);
    let rem = safe_rem(&random, modulo);
    Bool::and(
        ctx,
        &[&modulo_positive, &win_in_range, &rem._eq(winning_value)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_has_commit_reveal_pattern_detects_selector_and_entropy_ops() {
        let commit = selector("commit(bytes32)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&commit);
        bytecode.extend_from_slice(&[0x20, 0x55, 0x54, 0x06, 0x00]);
        assert!(has_commit_reveal_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_has_commit_reveal_pattern_rejects_missing_commit_reveal_surface() {
        let bytecode = Bytes::from(vec![0x20, 0x55, 0x54, 0x06, 0x00]);
        assert!(!has_commit_reveal_pattern(&bytecode));
    }

    #[test]
    fn test_reveal_outcome_wins_rejects_zero_modulo() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let leaked_seed = BV::from_u64(&ctx, 7, 256);
        let timestamp_next = BV::from_u64(&ctx, 1000, 256);
        let prevrandao = BV::from_u64(&ctx, 1234, 256);
        let modulo = BV::from_u64(&ctx, 0, 256);
        let winning = BV::from_u64(&ctx, 0, 256);

        solver.assert(&reveal_outcome_wins(
            &ctx,
            &leaked_seed,
            &timestamp_next,
            &prevrandao,
            &modulo,
            &winning,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
