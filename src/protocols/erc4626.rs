use crate::symbolic::utils::math::{extend_to_512, zero};
use revm::primitives::keccak256;
use revm::primitives::Bytes;
use z3::ast::{Ast, Bool, BV};
use z3::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erc4626Selector {
    TotalAssets,
    TotalSupply,
    Deposit,
    Mint,
    Withdraw,
    Redeem,
}

fn selector(signature: &str) -> u32 {
    let hash = keccak256(signature.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

fn bytecode_contains_selector(bytecode: &Bytes, selector: u32) -> bool {
    let selector_bytes = selector.to_be_bytes();
    let bytes = bytecode.as_ref();
    for i in 0..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x63 && bytes[i + 1..i + 5] == selector_bytes {
            return true;
        }
    }
    false
}

pub fn classify_selector(sel: u32) -> Option<Erc4626Selector> {
    let total_assets = selector("totalAssets()");
    let total_supply = selector("totalSupply()");
    let deposit = selector("deposit(uint256,address)");
    let mint = selector("mint(uint256,address)");
    let withdraw = selector("withdraw(uint256,address,address)");
    let redeem = selector("redeem(uint256,address,address)");

    if sel == total_assets {
        Some(Erc4626Selector::TotalAssets)
    } else if sel == total_supply {
        Some(Erc4626Selector::TotalSupply)
    } else if sel == deposit {
        Some(Erc4626Selector::Deposit)
    } else if sel == mint {
        Some(Erc4626Selector::Mint)
    } else if sel == withdraw {
        Some(Erc4626Selector::Withdraw)
    } else if sel == redeem {
        Some(Erc4626Selector::Redeem)
    } else {
        None
    }
}

pub fn all_selectors() -> Vec<u32> {
    vec![
        selector("totalAssets()"),
        selector("totalSupply()"),
        selector("deposit(uint256,address)"),
        selector("mint(uint256,address)"),
        selector("withdraw(uint256,address,address)"),
        selector("redeem(uint256,address,address)"),
    ]
}

pub fn known_vault_inflation_selectors() -> Vec<u32> {
    let mut selectors = vec![
        selector("totalAssets()"),
        selector("totalSupply()"),
        selector("deposit(uint256,address)"),
        selector("mint(uint256,address)"),
        selector("transfer(address,uint256)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn has_vault_inflation_pattern(bytecode: &Bytes) -> bool {
    let has_total_assets = bytecode_contains_selector(bytecode, selector("totalAssets()"));
    let has_total_supply = bytecode_contains_selector(bytecode, selector("totalSupply()"));
    let has_deposit_or_mint =
        bytecode_contains_selector(bytecode, selector("deposit(uint256,address)"))
            || bytecode_contains_selector(bytecode, selector("mint(uint256,address)"));
    let has_transfer = bytecode_contains_selector(bytecode, selector("transfer(address,uint256)"));
    let has_div = bytecode.as_ref().contains(&0x04); // DIV
    has_total_assets && has_total_supply && has_deposit_or_mint && has_transfer && has_div
}

pub fn has_share_rounding_griefing_pattern(bytecode: &Bytes) -> bool {
    let has_deposit = bytecode_contains_selector(bytecode, selector("deposit(uint256,address)"));
    let has_withdraw_or_redeem =
        bytecode_contains_selector(bytecode, selector("withdraw(uint256,address,address)"))
            || bytecode_contains_selector(bytecode, selector("redeem(uint256,address,address)"));
    let has_total_assets = bytecode_contains_selector(bytecode, selector("totalAssets()"));
    let has_total_supply = bytecode_contains_selector(bytecode, selector("totalSupply()"));
    let has_div = bytecode.as_ref().contains(&0x04); // DIV
    has_deposit && has_withdraw_or_redeem && has_total_assets && has_total_supply && has_div
}

pub fn first_depositor_inflation_drainable<'ctx>(
    ctx: &'ctx Context,
    total_supply: &BV<'ctx>,
    attacker_initial_deposit: &BV<'ctx>,
    donation_amount: &BV<'ctx>,
    victim_deposit: &BV<'ctx>,
    victim_shares_out: &BV<'ctx>,
) -> Bool<'ctx> {
    let total_assets = attacker_initial_deposit.bvadd(donation_amount);
    let no_overflow_assets = total_assets.bvuge(attacker_initial_deposit);
    let victim_share_numerator =
        extend_to_512(ctx, victim_deposit).bvmul(&extend_to_512(ctx, total_supply));
    let victim_zero_shares = victim_shares_out._eq(&zero(ctx));
    let strict_rounding_zero = victim_share_numerator.bvult(&extend_to_512(ctx, &total_assets));

    Bool::and(
        ctx,
        &[
            &total_supply._eq(&BV::from_u64(ctx, 1, 256)),
            &attacker_initial_deposit.bvugt(&zero(ctx)),
            &donation_amount.bvugt(&zero(ctx)),
            &victim_deposit.bvugt(&zero(ctx)),
            &victim_deposit.bvugt(donation_amount),
            &no_overflow_assets,
            &victim_zero_shares,
            &strict_rounding_zero,
        ],
    )
}

pub fn share_roundtrip_leaks_assets<'ctx>(
    ctx: &'ctx Context,
    attacker_assets_pre_roundtrip: &BV<'ctx>,
    attacker_assets_post_roundtrip: &BV<'ctx>,
) -> Bool<'ctx> {
    Bool::and(
        ctx,
        &[
            &attacker_assets_pre_roundtrip.bvugt(&zero(ctx)),
            &attacker_assets_post_roundtrip.bvugt(attacker_assets_pre_roundtrip),
        ],
    )
}

/// ERC-4626 invariant:
/// totalAssets / totalSupply must not decrease across a full cycle.
/// We compare ratios via 512-bit cross multiplication to avoid modular wrap.
pub fn assets_per_share_non_decreasing<'ctx>(
    ctx: &'ctx Context,
    initial_assets: &BV<'ctx>,
    initial_supply: &BV<'ctx>,
    final_assets: &BV<'ctx>,
    final_supply: &BV<'ctx>,
) -> Bool<'ctx> {
    let init_supply_zero = initial_supply._eq(&zero(ctx));
    let final_supply_zero = final_supply._eq(&zero(ctx));

    let lhs = extend_to_512(ctx, final_assets).bvmul(&extend_to_512(ctx, initial_supply));
    let rhs = extend_to_512(ctx, initial_assets).bvmul(&extend_to_512(ctx, final_supply));
    let ratio_non_decreasing = lhs.bvuge(&rhs);

    Bool::or(
        ctx,
        &[&init_supply_zero, &final_supply_zero, &ratio_non_decreasing],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_erc4626_ratio_violation_is_sat() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let init_assets = BV::from_u64(&ctx, 100, 256);
        let init_supply = BV::from_u64(&ctx, 100, 256);
        let final_assets = BV::from_u64(&ctx, 90, 256);
        let final_supply = BV::from_u64(&ctx, 100, 256);

        let inv = assets_per_share_non_decreasing(
            &ctx,
            &init_assets,
            &init_supply,
            &final_assets,
            &final_supply,
        );
        solver.assert(&inv.not());
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_erc4626_ratio_preservation_is_unsat_for_violation() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let init_assets = BV::from_u64(&ctx, 100, 256);
        let init_supply = BV::from_u64(&ctx, 100, 256);
        let final_assets = BV::from_u64(&ctx, 110, 256);
        let final_supply = BV::from_u64(&ctx, 100, 256);

        let inv = assets_per_share_non_decreasing(
            &ctx,
            &init_assets,
            &init_supply,
            &final_assets,
            &final_supply,
        );
        solver.assert(&inv.not());
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_has_vault_inflation_pattern_detects_erc4626_surface() {
        let total_assets = selector("totalAssets()");
        let total_supply = selector("totalSupply()");
        let deposit = selector("deposit(uint256,address)");
        let transfer = selector("transfer(address,uint256)");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&total_assets.to_be_bytes());
        bytecode.push(0x63);
        bytecode.extend_from_slice(&total_supply.to_be_bytes());
        bytecode.push(0x63);
        bytecode.extend_from_slice(&deposit.to_be_bytes());
        bytecode.push(0x63);
        bytecode.extend_from_slice(&transfer.to_be_bytes());
        bytecode.extend_from_slice(&[0x04, 0x00]); // DIV
        assert!(has_vault_inflation_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_first_depositor_inflation_drainable_rejects_nonzero_victim_shares() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let total_supply = BV::from_u64(&ctx, 1, 256);
        let attacker_initial_deposit = BV::from_u64(&ctx, 1, 256);
        let donation_amount = BV::from_u64(&ctx, 1_000_000, 256);
        let victim_deposit = BV::from_u64(&ctx, 999_999, 256);
        let victim_shares = BV::from_u64(&ctx, 1, 256);

        solver.assert(&first_depositor_inflation_drainable(
            &ctx,
            &total_supply,
            &attacker_initial_deposit,
            &donation_amount,
            &victim_deposit,
            &victim_shares,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_has_share_rounding_griefing_pattern_detects_roundtrip_surface() {
        let deposit = selector("deposit(uint256,address)");
        let withdraw = selector("withdraw(uint256,address,address)");
        let total_assets = selector("totalAssets()");
        let total_supply = selector("totalSupply()");
        let mut bytecode = vec![0x63];
        bytecode.extend_from_slice(&deposit.to_be_bytes());
        bytecode.push(0x63);
        bytecode.extend_from_slice(&withdraw.to_be_bytes());
        bytecode.push(0x63);
        bytecode.extend_from_slice(&total_assets.to_be_bytes());
        bytecode.push(0x63);
        bytecode.extend_from_slice(&total_supply.to_be_bytes());
        bytecode.extend_from_slice(&[0x04, 0x00]); // DIV
        assert!(has_share_rounding_griefing_pattern(&Bytes::from(bytecode)));
    }

    #[test]
    fn test_share_roundtrip_leaks_assets_rejects_non_profit_roundtrip() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let pre = BV::from_u64(&ctx, 100, 256);
        let post = BV::from_u64(&ctx, 100, 256);

        solver.assert(&share_roundtrip_leaks_assets(&ctx, &pre, &post));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
