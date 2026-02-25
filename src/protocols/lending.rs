use crate::symbolic::utils::math::{extend_to_512, safe_div, wad};
use z3::ast::{Ast, Bool, BV};

fn selector(signature: &str) -> [u8; 4] {
    let hash = alloy::primitives::keccak256(signature.as_bytes());
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

pub fn known_ltv_lag_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("borrow(uint256)"),
        selector("borrow(address,uint256,uint256,uint16,address)"),
        selector("supply(uint256)"),
        selector("supply(address,uint256,address,uint16)"),
        selector("withdraw(uint256)"),
        selector("withdraw(address,uint256,address)"),
        selector("liquidationCall(address,address,address,uint256,bool)"),
        selector("liquidateBorrow(address,uint256,address)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

/// Formal model of a lending protocol exchange rate
/// exchange_rate = (total_cash + total_borrows - total_reserves) / total_supply
/// For symbolic purposes, we often treat the exchange rate as a symbolic multiplier
/// constrained by reasonable bounds (e.g., 1.0 <= rate <= 1.5).
///
/// Arithmetic in 512-bit to prevent overflow (same pattern as uniswap_v2.rs::get_amount_out).
/// Max intermediate product: 2^256 × 2^256 = 2^512, but safe_div handles this within 512-bit.
pub fn get_redemption_amount<'ctx>(
    c_token_amount: &BV<'ctx>,
    exchange_rate: &BV<'ctx>,
) -> BV<'ctx> {
    // redeem_amount = c_token_amount * exchange_rate / 1e18
    let ctx = c_token_amount.get_ctx();
    let ct_512 = extend_to_512(ctx, c_token_amount);
    let er_512 = extend_to_512(ctx, exchange_rate);
    let wad_512 = extend_to_512(ctx, &wad(ctx));

    safe_div(&ct_512.bvmul(&er_512), &wad_512).extract(255, 0)
}

pub fn get_mint_amount<'ctx>(underlying_amount: &BV<'ctx>, exchange_rate: &BV<'ctx>) -> BV<'ctx> {
    // mint_amount = underlying_amount * 1e18 / exchange_rate
    let ctx = underlying_amount.get_ctx();
    let ua_512 = extend_to_512(ctx, underlying_amount);
    let wad_512 = extend_to_512(ctx, &wad(ctx));
    let er_512 = extend_to_512(ctx, exchange_rate);

    safe_div(&ua_512.bvmul(&wad_512), &er_512).extract(255, 0)
}

/// Check if a position is liquidatable (Health Factor < 1.0).
/// Uses 512-bit math to prevent overflow.
///
/// Condition:
/// (CollateralValue * LiquidationThreshold) < DebtValue * LTV_PRECISION
///
/// `liquidation_threshold` is typically in BPS (e.g. 8000 = 80%) or Wad (1e18).
/// We assume `liquidation_threshold` is normalized such that `1.0` is the base.
/// If passing BPS (e.g. 8000), `precision` should be 10000.
/// If passing WAD (e.g. 0.8e18), `precision` should be 1e18.
pub fn is_liquidatable<'ctx>(
    ctx: &'ctx z3::Context,
    collateral_value: &BV<'ctx>, // Total value in Reference Currency (e.g. USD/ETH)
    debt_value: &BV<'ctx>,       // Total value in Reference Currency
    liquidation_threshold: &BV<'ctx>,
    precision: &BV<'ctx>,
) -> z3::ast::Bool<'ctx> {
    let col_512 = extend_to_512(ctx, collateral_value);
    let debt_512 = extend_to_512(ctx, debt_value);
    let thresh_512 = extend_to_512(ctx, liquidation_threshold);
    let prec_512 = extend_to_512(ctx, precision);

    // Max Borrow = Collateral * Threshold / Precision
    // Liquidatable if Debt > Max Borrow
    // => Debt * Precision > Collateral * Threshold

    let capacity = col_512.bvmul(&thresh_512);
    let liability = debt_512.bvmul(&prec_512);

    liability.bvugt(&capacity)
}

/// Check if a user is insolvent (Bad Debt).
/// Debt Value > Collateral Value.
/// This means the protocol essentially loses money if they liquidate.
pub fn is_insolvent<'ctx>(
    ctx: &'ctx z3::Context,
    collateral_value: &BV<'ctx>,
    debt_value: &BV<'ctx>,
) -> z3::ast::Bool<'ctx> {
    let col_512 = extend_to_512(ctx, collateral_value);
    let debt_512 = extend_to_512(ctx, debt_value);

    debt_512.bvugt(&col_512)
}

/// Apply a bps-denominated collateral drop to model volatility shocks while the oracle is stale.
pub fn value_after_bps_drop<'ctx>(
    ctx: &'ctx z3::Context,
    value: &BV<'ctx>,
    drop_bps: u64,
) -> BV<'ctx> {
    let scale = extend_to_512(ctx, &BV::from_u64(ctx, 10_000, 256));
    let keep_bps = 10_000u64.saturating_sub(drop_bps.min(10_000));
    let keep = extend_to_512(ctx, &BV::from_u64(ctx, keep_bps, 256));
    safe_div(&extend_to_512(ctx, value).bvmul(&keep), &scale).extract(255, 0)
}

/// Check whether a position is at least a given LTV threshold in bps.
pub fn ltv_ratio_at_least_bps<'ctx>(
    ctx: &'ctx z3::Context,
    collateral_value: &BV<'ctx>,
    debt_value: &BV<'ctx>,
    min_ltv_bps: u64,
    precision: &BV<'ctx>,
) -> Bool<'ctx> {
    let debt_512 = extend_to_512(ctx, debt_value);
    let precision_512 = extend_to_512(ctx, precision);
    let collateral_512 = extend_to_512(ctx, collateral_value);
    let min_ltv_512 = extend_to_512(ctx, &BV::from_u64(ctx, min_ltv_bps, 256));
    debt_512
        .bvmul(&precision_512)
        .bvuge(&collateral_512.bvmul(&min_ltv_512))
}

/// Aave/Compound-style supply cap constraint.
/// `supply_cap == 0` is treated as "uncapped".
pub fn supply_cap_allows_supply<'ctx>(
    ctx: &'ctx z3::Context,
    total_supplied: &BV<'ctx>,
    supply_amount: &BV<'ctx>,
    supply_cap: &BV<'ctx>,
) -> Bool<'ctx> {
    let uncapped = supply_cap._eq(&BV::from_u64(ctx, 0, 256));
    let new_total = total_supplied.bvadd(supply_amount);
    let no_overflow = new_total.bvuge(total_supplied);
    let within_cap = new_total.bvule(supply_cap);
    let capped_allowed = Bool::and(ctx, &[&no_overflow, &within_cap]);
    Bool::or(ctx, &[&uncapped, &capped_allowed])
}

/// Isolation Mode borrow gate:
/// if isolation mode is enabled, borrowed asset must be isolation-borrowable and
/// aggregate isolation debt must stay under the debt ceiling.
pub fn isolation_mode_borrow_allowed<'ctx>(
    ctx: &'ctx z3::Context,
    isolation_mode_enabled: &Bool<'ctx>,
    asset_borrowable_in_isolation: &Bool<'ctx>,
    total_isolation_debt: &BV<'ctx>,
    borrow_amount: &BV<'ctx>,
    debt_ceiling: &BV<'ctx>,
) -> Bool<'ctx> {
    let new_debt = total_isolation_debt.bvadd(borrow_amount);
    let no_overflow = new_debt.bvuge(total_isolation_debt);
    let within_ceiling = new_debt.bvule(debt_ceiling);
    let gated = Bool::and(
        ctx,
        &[asset_borrowable_in_isolation, &no_overflow, &within_ceiling],
    );
    Bool::or(ctx, &[&isolation_mode_enabled.not(), &gated])
}

/// E-Mode borrow gate:
/// if enabled, assets must remain within the same efficiency category and
/// debt-after-borrow must not exceed E-Mode capacity.
#[allow(clippy::too_many_arguments)]
pub fn e_mode_borrow_allowed<'ctx>(
    ctx: &'ctx z3::Context,
    e_mode_enabled: &Bool<'ctx>,
    same_emode_category: &Bool<'ctx>,
    collateral_value: &BV<'ctx>,
    current_debt_value: &BV<'ctx>,
    borrow_value: &BV<'ctx>,
    e_mode_ltv: &BV<'ctx>,
    precision: &BV<'ctx>,
) -> Bool<'ctx> {
    let debt_after = current_debt_value.bvadd(borrow_value);
    let no_overflow = debt_after.bvuge(current_debt_value);

    let capacity = extend_to_512(ctx, collateral_value).bvmul(&extend_to_512(ctx, e_mode_ltv));
    let liability = extend_to_512(ctx, &debt_after).bvmul(&extend_to_512(ctx, precision));
    let within_capacity = liability.bvule(&capacity);

    let enabled_path = Bool::and(ctx, &[same_emode_category, &no_overflow, &within_capacity]);
    Bool::or(ctx, &[&e_mode_enabled.not(), &enabled_path])
}

/// Multiply two fixed-point numbers with a shared scale: floor(a*b/scale).
pub fn mul_scaled<'ctx>(
    ctx: &'ctx z3::Context,
    a: &BV<'ctx>,
    b: &BV<'ctx>,
    scale: &BV<'ctx>,
) -> BV<'ctx> {
    let a_512 = extend_to_512(ctx, a);
    let b_512 = extend_to_512(ctx, b);
    let scale_512 = extend_to_512(ctx, scale);
    safe_div(&a_512.bvmul(&b_512), &scale_512).extract(255, 0)
}

/// Exponentiation by squaring under fixed-point scaling.
///
/// Returns `base^exp` under the invariant that all multiplies are `mul_scaled(.., scale)`.
/// - `exp=0` returns `scale` (i.e. 1.0).
pub fn pow_scaled_u64<'ctx>(
    ctx: &'ctx z3::Context,
    base: &BV<'ctx>,
    mut exp: u64,
    scale: &BV<'ctx>,
) -> BV<'ctx> {
    let mut result = scale.clone();
    let mut acc = base.clone();
    while exp > 0 {
        if (exp & 1) == 1 {
            result = mul_scaled(ctx, &result, &acc, scale);
        }
        exp >>= 1;
        if exp > 0 {
            acc = mul_scaled(ctx, &acc, &acc, scale);
        }
    }
    result
}

/// Apply an index ratio to a balance: `balance_after = balance_before * index_after / index_before`.
///
/// This models both:
/// - Aave-style scaled balances (balance = scaled * index)
/// - Compound-style borrow balances (balance = principal * borrowIndex / borrowIndex_at_borrow)
pub fn apply_index_ratio<'ctx>(
    ctx: &'ctx z3::Context,
    balance_before: &BV<'ctx>,
    index_before: &BV<'ctx>,
    index_after: &BV<'ctx>,
) -> BV<'ctx> {
    let bal_512 = extend_to_512(ctx, balance_before);
    let idx_after_512 = extend_to_512(ctx, index_after);
    let idx_before_512 = extend_to_512(ctx, index_before);
    safe_div(&bal_512.bvmul(&idx_after_512), &idx_before_512).extract(255, 0)
}

/// Compound-style per-block simple interest accrual for `borrowIndex`.
///
/// Compound v2 uses simple interest per block:
/// - `interest_accumulated_wad = borrow_rate_per_block_wad * delta_blocks`
/// - `borrow_index_after = borrow_index_before * (WAD + interest_accumulated_wad) / WAD`
pub fn compound_borrow_index_simple_after_blocks_wad<'ctx>(
    ctx: &'ctx z3::Context,
    borrow_index_before_wad: &BV<'ctx>,
    borrow_rate_per_block_wad: &BV<'ctx>,
    delta_blocks: u64,
) -> BV<'ctx> {
    let wad = wad(ctx);
    let delta = BV::from_u64(ctx, delta_blocks, 256);
    let interest_512 =
        extend_to_512(ctx, borrow_rate_per_block_wad).bvmul(&extend_to_512(ctx, &delta));
    let factor_wad = extend_to_512(ctx, &wad)
        .bvadd(&interest_512)
        .extract(255, 0);
    mul_scaled(ctx, borrow_index_before_wad, &factor_wad, &wad)
}

/// Aave-style per-block compounding accrual for an index.
///
/// This is a discrete per-block model:
/// - `growth_per_block_wad = WAD + rate_per_block_wad`
/// - `index_after = index_before * (growth_per_block_wad ^ delta_blocks) / WAD`
pub fn aave_index_compound_after_blocks_wad<'ctx>(
    ctx: &'ctx z3::Context,
    index_before_wad: &BV<'ctx>,
    rate_per_block_wad: &BV<'ctx>,
    delta_blocks: u64,
) -> BV<'ctx> {
    let wad = wad(ctx);
    let growth = wad.bvadd(rate_per_block_wad);
    let factor = pow_scaled_u64(ctx, &growth, delta_blocks, &wad);
    mul_scaled(ctx, index_before_wad, &factor, &wad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_supply_cap_blocks_over_cap_supply() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let total = BV::from_u64(&ctx, 900, 256);
        let add = BV::from_u64(&ctx, 200, 256);
        let cap = BV::from_u64(&ctx, 1000, 256);
        let allowed = supply_cap_allows_supply(&ctx, &total, &add, &cap);
        solver.assert(&allowed);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_isolation_mode_requires_borrowable_asset() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let enabled = Bool::from_bool(&ctx, true);
        let borrowable = Bool::from_bool(&ctx, false);
        let total_debt = BV::from_u64(&ctx, 100, 256);
        let borrow = BV::from_u64(&ctx, 10, 256);
        let ceiling = BV::from_u64(&ctx, 200, 256);

        let allowed = isolation_mode_borrow_allowed(
            &ctx,
            &enabled,
            &borrowable,
            &total_debt,
            &borrow,
            &ceiling,
        );
        solver.assert(&allowed);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_e_mode_blocks_cross_category_borrow() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let enabled = Bool::from_bool(&ctx, true);
        let same_cat = Bool::from_bool(&ctx, false);
        let collateral = BV::from_u64(&ctx, 1000, 256);
        let debt = BV::from_u64(&ctx, 200, 256);
        let borrow = BV::from_u64(&ctx, 100, 256);
        let ltv = BV::from_u64(&ctx, 9500, 256);
        let precision = BV::from_u64(&ctx, 10000, 256);

        let allowed = e_mode_borrow_allowed(
            &ctx,
            &enabled,
            &same_cat,
            &collateral,
            &debt,
            &borrow,
            &ltv,
            &precision,
        );
        solver.assert(&allowed);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }

    #[test]
    fn test_value_after_bps_drop_halves_value() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let value = BV::from_u64(&ctx, 1_000, 256);
        let dropped = value_after_bps_drop(&ctx, &value, 5_000);

        solver.assert(&dropped._eq(&BV::from_u64(&ctx, 500, 256)));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_ltv_ratio_at_least_bps_detects_near_max_ltv() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let collateral = BV::from_u64(&ctx, 10_000, 256);
        let debt = BV::from_u64(&ctx, 8_800, 256);
        let precision = BV::from_u64(&ctx, 10_000, 256);

        solver.assert(&ltv_ratio_at_least_bps(
            &ctx,
            &collateral,
            &debt,
            8_700,
            &precision,
        ));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_ltv_ratio_at_least_bps_rejects_low_ltv() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let collateral = BV::from_u64(&ctx, 10_000, 256);
        let debt = BV::from_u64(&ctx, 7_000, 256);
        let precision = BV::from_u64(&ctx, 10_000, 256);

        solver.assert(&ltv_ratio_at_least_bps(
            &ctx,
            &collateral,
            &debt,
            8_700,
            &precision,
        ));
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
