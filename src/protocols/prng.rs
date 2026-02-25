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

fn bytecode_contains_selector(bytecode: &Bytes, selector: [u8; 4]) -> bool {
    let bytes = bytecode.as_ref();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 && bytes[i + 1..i + 5] == selector {
            return true;
        }
    }
    false
}

pub fn known_weak_prng_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("play(uint256)"),
        selector("bet(uint256)"),
        selector("rollDice(uint256)"),
        selector("spin(uint256)"),
        selector("draw(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_gambling_scanner_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("play(uint256)"),
        selector("bet(uint256)"),
        selector("rollDice(uint256)"),
        selector("spin(uint256)"),
        selector("draw(uint256)"),
        selector("claimPrize()"),
        selector("claim()"),
        selector("withdraw()"),
        selector("withdraw(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_weak_prng_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let mut has_entropy = false;
    let mut has_sha3 = false;
    let mut has_mod = false;

    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        match op {
            0x20 => has_sha3 = true,                  // SHA3
            0x40 | 0x42 | 0x44 => has_entropy = true, // BLOCKHASH/TIMESTAMP/PREVRANDAO
            0x06 => has_mod = true,                   // MOD
            0x60..=0x7f => {
                let push_len = (op - 0x5f) as usize;
                i = i.saturating_add(push_len);
            }
            _ => {}
        }
        i += 1;
    }

    has_entropy && has_sha3 && has_mod
}

pub fn has_gambling_contract_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let mut has_entropy = false;
    let mut has_mod = false;
    let mut has_value_payout_surface = false;
    let mut has_callvalue = false;

    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        match op {
            0x40 | 0x42 | 0x44 => has_entropy = true, // BLOCKHASH/TIMESTAMP/PREVRANDAO
            0x06 => has_mod = true,                   // MOD
            0x34 => has_callvalue = true,             // CALLVALUE
            0xf1 | 0xff => has_value_payout_surface = true, // CALL / SELFDESTRUCT
            0x60..=0x7f => {
                let push_len = (op - 0x5f) as usize;
                i = i.saturating_add(push_len);
            }
            _ => {}
        }
        i += 1;
    }

    let has_claim_selector = bytecode_contains_selector(bytecode, selector("claimPrize()"))
        || bytecode_contains_selector(bytecode, selector("claim()"))
        || bytecode_contains_selector(bytecode, selector("withdraw()"))
        || bytecode_contains_selector(bytecode, selector("withdraw(uint256)"));

    has_entropy && has_mod && has_value_payout_surface && (has_callvalue || has_claim_selector)
}

pub fn next_block_timestamp_in_range<'ctx>(
    ctx: &'ctx Context,
    current_timestamp: &BV<'ctx>,
    next_timestamp: &BV<'ctx>,
    max_drift_seconds: u64,
) -> Bool<'ctx> {
    let one = BV::from_u64(ctx, 1, 256);
    let max_delta = BV::from_u64(ctx, max_drift_seconds.max(1), 256);
    let min_next = current_timestamp.bvadd(&one);
    let max_next = current_timestamp.bvadd(&max_delta);
    let no_overflow_min = min_next.bvuge(current_timestamp);
    let no_overflow_max = max_next.bvuge(current_timestamp);
    Bool::and(
        ctx,
        &[
            &no_overflow_min,
            &no_overflow_max,
            &next_timestamp.bvuge(&min_next),
            &next_timestamp.bvule(&max_next),
        ],
    )
}

pub fn wins_modulo<'ctx>(
    ctx: &'ctx Context,
    random_value: &BV<'ctx>,
    modulo: &BV<'ctx>,
    winning_value: &BV<'ctx>,
) -> Bool<'ctx> {
    let modulo_positive = modulo.bvugt(&zero(ctx));
    let winning_in_range = winning_value.bvult(modulo);
    let remainder = safe_rem(random_value, modulo);
    Bool::and(
        ctx,
        &[
            &modulo_positive,
            &winning_in_range,
            &remainder._eq(winning_value),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_has_weak_prng_pattern_detects_entropy_sha3_mod_sequence() {
        // TIMESTAMP (42), SHA3 (20), MOD (06)
        let bytecode = Bytes::from(vec![0x42, 0x20, 0x06, 0x00]);
        assert!(has_weak_prng_pattern(&bytecode));
    }

    #[test]
    fn test_has_weak_prng_pattern_rejects_missing_entropy_opcodes() {
        // SHA3 + MOD without block entropy source
        let bytecode = Bytes::from(vec![0x20, 0x06, 0x00]);
        assert!(!has_weak_prng_pattern(&bytecode));
    }

    #[test]
    fn test_has_gambling_contract_pattern_detects_entropy_and_payout_surface() {
        // TIMESTAMP + MOD + CALLVALUE + CALL
        let bytecode = Bytes::from(vec![0x42, 0x06, 0x34, 0xf1, 0x00]);
        assert!(has_gambling_contract_pattern(&bytecode));
    }

    #[test]
    fn test_has_gambling_contract_pattern_rejects_missing_payout_surface() {
        // Entropy + MOD + CALLVALUE without CALL/SELFDESTRUCT
        let bytecode = Bytes::from(vec![0x44, 0x06, 0x34, 0x00]);
        assert!(!has_gambling_contract_pattern(&bytecode));
    }

    #[test]
    fn test_next_block_timestamp_in_range_accepts_short_forward_step() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let current = BV::from_u64(&ctx, 1_000, 256);
        let next = BV::from_u64(&ctx, 1_012, 256);
        solver.assert(&next_block_timestamp_in_range(&ctx, &current, &next, 15));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_wins_modulo_rejects_out_of_range_winning_value() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let random = BV::from_u64(&ctx, 17, 256);
        let modulo = BV::from_u64(&ctx, 8, 256);
        let winning = BV::from_u64(&ctx, 9, 256);
        solver.assert(&wins_modulo(&ctx, &random, &modulo, &winning));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
