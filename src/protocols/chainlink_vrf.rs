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

pub fn known_vrf_fulfill_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("rawFulfillRandomWords(uint256,uint256[])"),
        selector("fulfillRandomWords(uint256,uint256[])"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_vrf_claim_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("claimPrize()"),
        selector("claim()"),
        selector("claim(uint256)"),
        selector("settle()"),
        selector("withdrawWinnings()"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_vrf_timing_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_sstore = bytes.contains(&0x55);
    let has_sload = bytes.contains(&0x54);
    let has_fulfill_selector = known_vrf_fulfill_selectors()
        .iter()
        .copied()
        .any(|sel| bytecode_contains_selector(bytecode, sel));
    let has_claim_selector = known_vrf_claim_selectors()
        .iter()
        .copied()
        .any(|sel| bytecode_contains_selector(bytecode, sel));

    has_sstore && has_sload && has_fulfill_selector && has_claim_selector
}

pub fn same_block_claim_window<'ctx>(
    ctx: &'ctx Context,
    fulfill_block: &BV<'ctx>,
    claim_block: &BV<'ctx>,
) -> Bool<'ctx> {
    let nonzero = fulfill_block.bvugt(&zero(ctx));
    Bool::and(ctx, &[&nonzero, &claim_block._eq(fulfill_block)])
}

pub fn vrf_claim_wins<'ctx>(
    ctx: &'ctx Context,
    random_word: &BV<'ctx>,
    modulo: &BV<'ctx>,
    winning_value: &BV<'ctx>,
) -> Bool<'ctx> {
    let modulo_positive = modulo.bvugt(&zero(ctx));
    let winning_in_range = winning_value.bvult(modulo);
    let remainder = safe_rem(random_word, modulo);
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
    fn test_has_vrf_timing_pattern_detects_fulfill_and_claim_surface() {
        let fulfill = selector("rawFulfillRandomWords(uint256,uint256[])");
        let claim = selector("claimPrize()");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&fulfill);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&claim);
        bytecode.extend_from_slice(&[0x55, 0x54, 0x00]); // SSTORE + SLOAD
        assert!(has_vrf_timing_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_has_vrf_timing_pattern_rejects_missing_claim_surface() {
        let fulfill = selector("rawFulfillRandomWords(uint256,uint256[])");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&fulfill);
        bytecode.extend_from_slice(&[0x55, 0x54, 0x00]); // no claim selector
        assert!(!has_vrf_timing_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_same_block_claim_window_requires_equal_blocks() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let fulfill = BV::from_u64(&ctx, 100, 256);
        let claim = BV::from_u64(&ctx, 101, 256);

        solver.assert(&same_block_claim_window(&ctx, &fulfill, &claim));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_vrf_claim_wins_rejects_out_of_range_winning_value() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let random_word = BV::from_u64(&ctx, 5, 256);
        let modulo = BV::from_u64(&ctx, 4, 256);
        let winning = BV::from_u64(&ctx, 5, 256);

        solver.assert(&vrf_claim_wins(&ctx, &random_word, &modulo, &winning));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
