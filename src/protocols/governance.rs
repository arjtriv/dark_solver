use crate::symbolic::utils::math::{extend_to_512, zero};
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

pub fn known_governance_flash_vote_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("propose(address[],uint256[],bytes[],string)"),
        selector("propose(address[],uint256[],string)"),
        selector("propose(bytes)"),
        selector("vote(uint256)"),
        selector("castVote(uint256,uint8)"),
        selector("castVoteBySig(uint256,uint8,uint8,bytes32,bytes32)"),
        selector("balanceOf(address)"),
        selector("transfer(address,uint256)"),
        selector("execute(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_quorum_manipulation_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("quorum(uint256)"),
        selector("quorum()"),
        selector("totalSupply()"),
        selector("mint(uint256)"),
        selector("wrap(uint256)"),
        selector("deposit(uint256)"),
        selector("vote(uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn known_delegatee_hijack_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("delegate(address)"),
        selector("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)"),
        selector("getVotes(address)"),
        selector("getCurrentVotes(address)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_flash_loan_governance_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_vote_selector = bytecode_contains_selector(bytecode, selector("vote(uint256)"))
        || bytecode_contains_selector(bytecode, selector("castVote(uint256,uint8)"))
        || bytecode_contains_selector(
            bytecode,
            selector("castVoteBySig(uint256,uint8,uint8,bytes32,bytes32)"),
        );
    let has_propose_selector =
        bytecode_contains_selector(
            bytecode,
            selector("propose(address[],uint256[],bytes[],string)"),
        ) || bytecode_contains_selector(bytecode, selector("propose(address[],uint256[],string)"))
            || bytecode_contains_selector(bytecode, selector("propose(bytes)"));
    let has_current_balance_vote =
        bytecode_contains_selector(bytecode, selector("balanceOf(address)"));
    let has_snapshot_vote =
        bytecode_contains_selector(bytecode, selector("getPriorVotes(address,uint256)"))
            || bytecode_contains_selector(bytecode, selector("getPastVotes(address,uint256)"));
    let has_state_surface = bytes.contains(&0x54) && bytes.contains(&0x55); // SLOAD + SSTORE

    has_vote_selector
        && has_propose_selector
        && has_current_balance_vote
        && !has_snapshot_vote
        && has_state_surface
}

pub fn has_quorum_manipulation_pattern(bytecode: &Bytes) -> bool {
    let has_quorum_selector = bytecode_contains_selector(bytecode, selector("quorum(uint256)"))
        || bytecode_contains_selector(bytecode, selector("quorum()"));
    let has_total_supply_selector = bytecode_contains_selector(bytecode, selector("totalSupply()"));
    let has_supply_mutator_selector =
        bytecode_contains_selector(bytecode, selector("mint(uint256)"))
            || bytecode_contains_selector(bytecode, selector("wrap(uint256)"))
            || bytecode_contains_selector(bytecode, selector("deposit(uint256)"));

    has_quorum_selector && has_total_supply_selector && has_supply_mutator_selector
}

pub fn has_delegatee_hijack_pattern(bytecode: &Bytes) -> bool {
    let bytes = bytecode.as_ref();
    let has_delegate_selector = bytecode_contains_selector(bytecode, selector("delegate(address)"))
        || bytecode_contains_selector(
            bytecode,
            selector("delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)"),
        );
    let has_vote_surface = bytecode_contains_selector(bytecode, selector("getVotes(address)"))
        || bytecode_contains_selector(bytecode, selector("getCurrentVotes(address)"));
    let has_delegate_state_write = bytes.contains(&0x55); // SSTORE

    // Heuristic owner/auth check pattern: CALLER + EQ + REVERT in same contract body.
    let has_owner_guard_pattern =
        bytes.contains(&0x33) && bytes.contains(&0x14) && bytes.contains(&0xfd);

    has_delegate_selector
        && has_vote_surface
        && has_delegate_state_write
        && !has_owner_guard_pattern
}

pub fn flash_loan_meets_quorum<'ctx>(
    ctx: &'ctx Context,
    flash_loan_amount: &BV<'ctx>,
    quorum_threshold: &BV<'ctx>,
) -> Bool<'ctx> {
    let quorum_positive = quorum_threshold.bvugt(&zero(ctx));
    Bool::and(
        ctx,
        &[&quorum_positive, &flash_loan_amount.bvuge(quorum_threshold)],
    )
}

pub fn quorum_ratio_satisfied_after_mint<'ctx>(
    ctx: &'ctx Context,
    attacker_balance: &BV<'ctx>,
    total_supply: &BV<'ctx>,
    mint_amount: &BV<'ctx>,
    quorum_ratio_bps: u64,
) -> Bool<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let quorum_ratio = extend_to_512(ctx, &BV::from_u64(ctx, quorum_ratio_bps, 256));

    let minted_supply = total_supply.bvadd(mint_amount);
    let no_overflow = minted_supply.bvuge(total_supply);
    let lhs = extend_to_512(ctx, attacker_balance).bvmul(&scale);
    let rhs = extend_to_512(ctx, &minted_supply).bvmul(&quorum_ratio);

    Bool::and(
        ctx,
        &[
            &total_supply.bvugt(&zero(ctx)),
            &mint_amount.bvugt(&zero(ctx)),
            &no_overflow,
            &lhs.bvuge(&rhs),
        ],
    )
}

pub fn unauthorized_delegate_to_attacker<'ctx>(
    ctx: &'ctx Context,
    caller_word: &BV<'ctx>,
    owner_word: &BV<'ctx>,
    delegatee_word: &BV<'ctx>,
    attacker_word: &BV<'ctx>,
    votes_before: &BV<'ctx>,
    votes_after: &BV<'ctx>,
) -> Bool<'ctx> {
    Bool::and(
        ctx,
        &[
            &caller_word._eq(owner_word).not(),
            &delegatee_word._eq(attacker_word),
            &votes_after.bvugt(votes_before),
        ],
    )
}

pub fn proposal_transfers_treasury<'ctx>(
    ctx: &'ctx Context,
    transfer_to: &BV<'ctx>,
    attacker_word: &BV<'ctx>,
    transfer_amount: &BV<'ctx>,
    treasury_balance: &BV<'ctx>,
) -> Bool<'ctx> {
    let treasury_positive = treasury_balance.bvugt(&zero(ctx));
    Bool::and(
        ctx,
        &[
            &treasury_positive,
            &transfer_to._eq(attacker_word),
            &transfer_amount._eq(treasury_balance),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Solver};

    #[test]
    fn test_has_flash_loan_governance_pattern_detects_no_snapshot_vote_surface() {
        let vote = selector("castVote(uint256,uint8)");
        let propose = selector("propose(address[],uint256[],bytes[],string)");
        let balance = selector("balanceOf(address)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&vote);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&propose);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&balance);
        bytecode.extend_from_slice(&[0x54, 0x55, 0x00]); // SLOAD + SSTORE
        assert!(has_flash_loan_governance_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_has_flash_loan_governance_pattern_rejects_snapshot_voting() {
        let vote = selector("castVote(uint256,uint8)");
        let propose = selector("propose(address[],uint256[],bytes[],string)");
        let balance = selector("balanceOf(address)");
        let snapshot = selector("getPriorVotes(address,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&vote);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&propose);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&balance);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&snapshot);
        bytecode.extend_from_slice(&[0x54, 0x55, 0x00]);
        assert!(!has_flash_loan_governance_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_flash_loan_meets_quorum_rejects_insufficient_loan() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let flash_loan_amount = BV::from_u64(&ctx, 99, 256);
        let quorum_threshold = BV::from_u64(&ctx, 100, 256);

        solver.assert(&flash_loan_meets_quorum(
            &ctx,
            &flash_loan_amount,
            &quorum_threshold,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_has_quorum_manipulation_pattern_detects_quorum_total_supply_and_mutator() {
        let quorum = selector("quorum(uint256)");
        let total_supply = selector("totalSupply()");
        let mint = selector("mint(uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&quorum);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&total_supply);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&mint);
        bytecode.push(0x00);
        assert!(has_quorum_manipulation_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_quorum_ratio_satisfied_after_mint_rejects_low_attacker_share() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let attacker_balance = BV::from_u64(&ctx, 50, 256);
        let total_supply = BV::from_u64(&ctx, 10_000, 256);
        let mint_amount = BV::from_u64(&ctx, 1_000, 256);

        solver.assert(&quorum_ratio_satisfied_after_mint(
            &ctx,
            &attacker_balance,
            &total_supply,
            &mint_amount,
            2000, // 20%
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_has_delegatee_hijack_pattern_detects_delegate_without_owner_guard() {
        let delegate = selector("delegate(address)");
        let votes = selector("getVotes(address)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&delegate);
        bytecode.push(0x63);
        bytecode.extend_from_slice(&votes);
        bytecode.extend_from_slice(&[0x55, 0x00]); // SSTORE
        assert!(has_delegatee_hijack_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_unauthorized_delegate_to_attacker_rejects_owner_caller() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let owner_word = BV::from_u64(&ctx, 7, 256);
        let caller_word = BV::from_u64(&ctx, 7, 256);
        let attacker_word = BV::from_u64(&ctx, 9, 256);
        let votes_before = BV::from_u64(&ctx, 10, 256);
        let votes_after = BV::from_u64(&ctx, 11, 256);

        solver.assert(&unauthorized_delegate_to_attacker(
            &ctx,
            &caller_word,
            &owner_word,
            &attacker_word,
            &attacker_word,
            &votes_before,
            &votes_after,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
