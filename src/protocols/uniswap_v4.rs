use alloy::primitives::{Address, U256};
use revm::primitives::keccak256;
use std::collections::HashMap;

const HOOK_SIGNATURES: [&str; 10] = [
    "beforeInitialize(address,(address,address,uint24,int24,address),uint160,bytes)",
    "afterInitialize(address,(address,address,uint24,int24,address),uint160,int24,bytes)",
    "beforeAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
    "afterAddLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int256,int256),bytes)",
    "beforeRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
    "afterRemoveLiquidity(address,(address,address,uint24,int24,address),(int24,int24,int256,bytes32),(int256,int256),bytes)",
    "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
    "afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),(int256,int256),bytes)",
    "beforeDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
    "afterDonate(address,(address,address,uint24,int24,address),uint256,uint256,bytes)",
];

const POOL_MANAGER_SIGNATURES: [&str; 3] = [
    "swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
    "modifyLiquidity((address,address,uint24,int24,address),(int24,int24,int256,bytes32),bytes)",
    "donate((address,address,uint24,int24,address),uint256,uint256,bytes)",
];

fn selector_from_signature(signature: &str) -> u32 {
    let hash = keccak256(signature.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

pub fn hook_selectors() -> Vec<u32> {
    HOOK_SIGNATURES
        .iter()
        .map(|sig| selector_from_signature(sig))
        .collect()
}

pub fn is_hook_callback_selector(selector: u32) -> bool {
    HOOK_SIGNATURES
        .iter()
        .any(|sig| selector_from_signature(sig) == selector)
}

pub fn pool_manager_selectors() -> Vec<u32> {
    POOL_MANAGER_SIGNATURES
        .iter()
        .map(|sig| selector_from_signature(sig))
        .collect()
}

pub fn is_pool_manager_selector(selector: u32) -> bool {
    POOL_MANAGER_SIGNATURES
        .iter()
        .any(|sig| selector_from_signature(sig) == selector)
}

pub fn modeled_pool_manager_return_words(selector: u32) -> usize {
    let swap = selector_from_signature(POOL_MANAGER_SIGNATURES[0]);
    let modify = selector_from_signature(POOL_MANAGER_SIGNATURES[1]);
    let donate = selector_from_signature(POOL_MANAGER_SIGNATURES[2]);
    if selector == modify {
        4 // callerDelta + feesAccrued (each is a 2-word BalanceDelta)
    } else if selector == swap || selector == donate {
        2 // BalanceDelta
    } else {
        1
    }
}

pub fn modeled_hook_return_words(selector: u32) -> usize {
    let before_swap = selector_from_signature(HOOK_SIGNATURES[6]);
    let after_swap = selector_from_signature(HOOK_SIGNATURES[7]);
    let before_add = selector_from_signature(HOOK_SIGNATURES[2]);
    let after_add = selector_from_signature(HOOK_SIGNATURES[3]);
    let before_remove = selector_from_signature(HOOK_SIGNATURES[4]);
    let after_remove = selector_from_signature(HOOK_SIGNATURES[5]);

    if selector == before_swap {
        3
    } else if selector == after_swap
        || selector == before_add
        || selector == after_add
        || selector == before_remove
        || selector == after_remove
    {
        2
    } else {
        1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub currency0: Address,
    pub currency1: Address,
    pub fee_pips: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
}

#[derive(Clone, Copy, Debug)]
pub struct PoolState {
    pub reserve0: U256,
    pub reserve1: U256,
    pub liquidity: U256,
}

#[derive(Clone, Debug, Default)]
pub struct CurrencyDelta {
    /// Amount the caller must pay into the pool manager.
    pub to_pool: U256,
    /// Amount the caller should receive from the pool manager.
    pub from_pool: U256,
}

#[derive(Clone, Debug, Default)]
pub struct FlashAccounting {
    pub deltas: HashMap<Address, CurrencyDelta>,
}

impl FlashAccounting {
    pub fn debit_to_pool(&mut self, currency: Address, amount: U256) -> bool {
        if amount.is_zero() {
            return true;
        }
        let entry = self.deltas.entry(currency).or_default();
        match entry.to_pool.checked_add(amount) {
            Some(v) => {
                entry.to_pool = v;
                true
            }
            None => false,
        }
    }

    pub fn credit_from_pool(&mut self, currency: Address, amount: U256) -> bool {
        if amount.is_zero() {
            return true;
        }
        let entry = self.deltas.entry(currency).or_default();
        match entry.from_pool.checked_add(amount) {
            Some(v) => {
                entry.from_pool = v;
                true
            }
            None => false,
        }
    }

    pub fn settle_transfer(
        &mut self,
        currency: Address,
        paid_to_pool: U256,
        received_from_pool: U256,
    ) -> bool {
        let entry = self.deltas.entry(currency).or_default();
        let next_to_pool = match entry.to_pool.checked_sub(paid_to_pool) {
            Some(v) => v,
            None => return false,
        };
        let next_from_pool = match entry.from_pool.checked_sub(received_from_pool) {
            Some(v) => v,
            None => return false,
        };
        entry.to_pool = next_to_pool;
        entry.from_pool = next_from_pool;
        true
    }

    pub fn is_fully_settled(&self) -> bool {
        self.deltas
            .values()
            .all(|delta| delta.to_pool.is_zero() && delta.from_pool.is_zero())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HookAdjustments {
    pub fee_override_pips: Option<u32>,
    pub delta0_to_pool: U256,
    pub delta1_to_pool: U256,
    pub delta0_from_pool: U256,
    pub delta1_from_pool: U256,
}

#[derive(Clone, Copy, Debug)]
pub struct SwapParams {
    pub zero_for_one: bool,
    pub amount_specified: U256,
    pub exact_input: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapOutcome {
    pub amount_in: U256,
    pub amount_out: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModifyPositionOutcome {
    pub liquidity_delta: U256,
    pub amount0: U256,
    pub amount1: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionAction {
    Add {
        amount0_desired: U256,
        amount1_desired: U256,
    },
    Remove {
        liquidity_to_burn: U256,
    },
}

fn calc_amount_out_cp(
    reserve_in: U256,
    reserve_out: U256,
    amount_in: U256,
    fee_pips: u32,
) -> Option<U256> {
    if reserve_in.is_zero() || reserve_out.is_zero() || amount_in.is_zero() || fee_pips >= 1_000_000
    {
        return None;
    }
    let amount_in_less_fee = amount_in
        .checked_mul(U256::from(1_000_000u64.saturating_sub(fee_pips as u64)))?
        / U256::from(1_000_000u64);
    if amount_in_less_fee.is_zero() {
        return Some(U256::ZERO);
    }
    let numer = reserve_out.checked_mul(amount_in_less_fee)?;
    let denom = reserve_in.checked_add(amount_in_less_fee)?;
    Some(numer / denom)
}

fn calc_amount_in_for_exact_out_cp(
    reserve_in: U256,
    reserve_out: U256,
    amount_out: U256,
    fee_pips: u32,
) -> Option<U256> {
    if reserve_in.is_zero()
        || reserve_out.is_zero()
        || amount_out.is_zero()
        || amount_out >= reserve_out
        || fee_pips >= 1_000_000
    {
        return None;
    }
    let numer = reserve_in
        .checked_mul(amount_out)?
        .checked_mul(U256::from(1_000_000u64))?;
    let denom = reserve_out
        .checked_sub(amount_out)?
        .checked_mul(U256::from(1_000_000u64.saturating_sub(fee_pips as u64)))?;
    Some(numer / denom + U256::from(1u64))
}

fn integer_sqrt(value: U256) -> U256 {
    if value.is_zero() {
        return U256::ZERO;
    }
    let mut z = value / U256::from(2u64) + U256::from(1u64);
    let mut y = value;
    while z < y {
        y = z;
        z = (value / z + z) / U256::from(2u64);
    }
    y
}

/// PoolManager `swap` model with flash-accounting delta tracking.
pub fn swap(
    key: &PoolKey,
    pool: &mut PoolState,
    params: SwapParams,
    hook: HookAdjustments,
    accounting: &mut FlashAccounting,
) -> Option<SwapOutcome> {
    if params.amount_specified.is_zero() {
        return None;
    }
    let fee = hook.fee_override_pips.unwrap_or(key.fee_pips);
    if fee >= 1_000_000 {
        return None;
    }

    let (amount_in, amount_out) = if params.exact_input {
        let exact_in = params.amount_specified;
        let out = if params.zero_for_one {
            calc_amount_out_cp(pool.reserve0, pool.reserve1, exact_in, fee)?
        } else {
            calc_amount_out_cp(pool.reserve1, pool.reserve0, exact_in, fee)?
        };
        (exact_in, out)
    } else {
        let exact_out = params.amount_specified;
        let required_in = if params.zero_for_one {
            calc_amount_in_for_exact_out_cp(pool.reserve0, pool.reserve1, exact_out, fee)?
        } else {
            calc_amount_in_for_exact_out_cp(pool.reserve1, pool.reserve0, exact_out, fee)?
        };
        (required_in, exact_out)
    };

    if params.zero_for_one {
        pool.reserve0 = pool.reserve0.checked_add(amount_in)?;
        pool.reserve1 = pool.reserve1.checked_sub(amount_out)?;
        accounting.debit_to_pool(key.currency0, amount_in);
        accounting.credit_from_pool(key.currency1, amount_out);
    } else {
        pool.reserve1 = pool.reserve1.checked_add(amount_in)?;
        pool.reserve0 = pool.reserve0.checked_sub(amount_out)?;
        accounting.debit_to_pool(key.currency1, amount_in);
        accounting.credit_from_pool(key.currency0, amount_out);
    }

    // Hook-level currency-delta adjustments.
    pool.reserve0 = pool.reserve0.checked_add(hook.delta0_to_pool)?;
    pool.reserve1 = pool.reserve1.checked_add(hook.delta1_to_pool)?;
    pool.reserve0 = pool.reserve0.checked_sub(hook.delta0_from_pool)?;
    pool.reserve1 = pool.reserve1.checked_sub(hook.delta1_from_pool)?;

    accounting.debit_to_pool(key.currency0, hook.delta0_to_pool);
    accounting.debit_to_pool(key.currency1, hook.delta1_to_pool);
    accounting.credit_from_pool(key.currency0, hook.delta0_from_pool);
    accounting.credit_from_pool(key.currency1, hook.delta1_from_pool);

    Some(SwapOutcome {
        amount_in,
        amount_out,
    })
}

/// PoolManager `modifyLiquidity` model (add/remove proportional liquidity).
pub fn modify_position(
    key: &PoolKey,
    pool: &mut PoolState,
    action: PositionAction,
    accounting: &mut FlashAccounting,
) -> Option<ModifyPositionOutcome> {
    match action {
        PositionAction::Add {
            amount0_desired,
            amount1_desired,
        } => {
            if amount0_desired.is_zero() || amount1_desired.is_zero() {
                return None;
            }

            let (liquidity_delta, amount0, amount1) = if pool.liquidity.is_zero() {
                let liq = integer_sqrt(amount0_desired.checked_mul(amount1_desired)?);
                if liq.is_zero() {
                    return None;
                }
                (liq, amount0_desired, amount1_desired)
            } else {
                if pool.reserve0.is_zero() || pool.reserve1.is_zero() {
                    return None;
                }
                let liq0 = amount0_desired.checked_mul(pool.liquidity)? / pool.reserve0;
                let liq1 = amount1_desired.checked_mul(pool.liquidity)? / pool.reserve1;
                let liq = liq0.min(liq1);
                if liq.is_zero() {
                    return None;
                }
                let used0 = liq.checked_mul(pool.reserve0)? / pool.liquidity;
                let used1 = liq.checked_mul(pool.reserve1)? / pool.liquidity;
                (liq, used0, used1)
            };

            pool.reserve0 = pool.reserve0.checked_add(amount0)?;
            pool.reserve1 = pool.reserve1.checked_add(amount1)?;
            pool.liquidity = pool.liquidity.checked_add(liquidity_delta)?;
            accounting.debit_to_pool(key.currency0, amount0);
            accounting.debit_to_pool(key.currency1, amount1);

            Some(ModifyPositionOutcome {
                liquidity_delta,
                amount0,
                amount1,
            })
        }
        PositionAction::Remove { liquidity_to_burn } => {
            if liquidity_to_burn.is_zero()
                || liquidity_to_burn > pool.liquidity
                || pool.liquidity.is_zero()
            {
                return None;
            }
            let amount0 = liquidity_to_burn.checked_mul(pool.reserve0)? / pool.liquidity;
            let amount1 = liquidity_to_burn.checked_mul(pool.reserve1)? / pool.liquidity;
            pool.reserve0 = pool.reserve0.checked_sub(amount0)?;
            pool.reserve1 = pool.reserve1.checked_sub(amount1)?;
            pool.liquidity = pool.liquidity.checked_sub(liquidity_to_burn)?;
            accounting.credit_from_pool(key.currency0, amount0);
            accounting.credit_from_pool(key.currency1, amount1);

            Some(ModifyPositionOutcome {
                liquidity_delta: liquidity_to_burn,
                amount0,
                amount1,
            })
        }
    }
}

/// PoolManager `donate` model.
pub fn donate(
    key: &PoolKey,
    pool: &mut PoolState,
    amount0: U256,
    amount1: U256,
    accounting: &mut FlashAccounting,
) -> Option<()> {
    if amount0.is_zero() && amount1.is_zero() {
        return Some(());
    }
    pool.reserve0 = pool.reserve0.checked_add(amount0)?;
    pool.reserve1 = pool.reserve1.checked_add(amount1)?;
    accounting.debit_to_pool(key.currency0, amount0);
    accounting.debit_to_pool(key.currency1, amount1);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognizes_hook_selector() {
        let selectors = hook_selectors();
        assert!(!selectors.is_empty());
        assert!(is_hook_callback_selector(selectors[0]));
    }

    #[test]
    fn test_rejects_non_hook_selector() {
        assert!(!is_hook_callback_selector(0x0902f1ac)); // getReserves()
    }

    #[test]
    fn test_modeled_hook_return_words_budget() {
        let selectors = hook_selectors();
        for selector in selectors {
            let words = modeled_hook_return_words(selector);
            assert!((1..=3).contains(&words));
        }
    }

    #[test]
    fn test_pool_manager_selector_recognition() {
        let selectors = pool_manager_selectors();
        assert_eq!(selectors.len(), 3);
        for s in selectors {
            assert!(is_pool_manager_selector(s));
            assert!((1..=4).contains(&modeled_pool_manager_return_words(s)));
        }
        assert!(!is_pool_manager_selector(0x0902f1ac));
    }

    #[test]
    fn test_swap_updates_pool_and_flash_deltas() {
        let token0 = Address::from([0x11; 20]);
        let token1 = Address::from([0x22; 20]);
        let mut pool = PoolState {
            reserve0: U256::from(1_000_000u64),
            reserve1: U256::from(1_000_000u64),
            liquidity: U256::from(1_000_000u64),
        };
        let key = PoolKey {
            currency0: token0,
            currency1: token1,
            fee_pips: 3_000,
            tick_spacing: 60,
            hooks: Address::ZERO,
        };
        let mut accounting = FlashAccounting::default();

        let out = swap(
            &key,
            &mut pool,
            SwapParams {
                zero_for_one: true,
                amount_specified: U256::from(10_000u64),
                exact_input: true,
            },
            HookAdjustments::default(),
            &mut accounting,
        )
        .expect("swap must succeed");

        assert!(out.amount_out > U256::ZERO);
        assert!(pool.reserve0 > U256::from(1_000_000u64));
        assert!(pool.reserve1 < U256::from(1_000_000u64));
        let delta0 = accounting.deltas.get(&token0).expect("token0 delta");
        let delta1 = accounting.deltas.get(&token1).expect("token1 delta");
        assert!(delta0.to_pool > U256::ZERO);
        assert!(delta1.from_pool > U256::ZERO);
    }

    #[test]
    fn test_modify_position_add_then_remove() {
        let token0 = Address::from([0x33; 20]);
        let token1 = Address::from([0x44; 20]);
        let key = PoolKey {
            currency0: token0,
            currency1: token1,
            fee_pips: 3_000,
            tick_spacing: 60,
            hooks: Address::ZERO,
        };
        let mut pool = PoolState {
            reserve0: U256::from(2_000_000u64),
            reserve1: U256::from(2_000_000u64),
            liquidity: U256::from(2_000_000u64),
        };
        let mut accounting = FlashAccounting::default();
        let add = modify_position(
            &key,
            &mut pool,
            PositionAction::Add {
                amount0_desired: U256::from(20_000u64),
                amount1_desired: U256::from(20_000u64),
            },
            &mut accounting,
        )
        .expect("add liquidity");
        assert!(add.liquidity_delta > U256::ZERO);

        let remove = modify_position(
            &key,
            &mut pool,
            PositionAction::Remove {
                liquidity_to_burn: add.liquidity_delta,
            },
            &mut accounting,
        )
        .expect("remove liquidity");
        assert!(remove.amount0 > U256::ZERO);
        assert!(remove.amount1 > U256::ZERO);
    }

    #[test]
    fn test_donate_tracks_delta() {
        let token0 = Address::from([0x55; 20]);
        let token1 = Address::from([0x66; 20]);
        let key = PoolKey {
            currency0: token0,
            currency1: token1,
            fee_pips: 3_000,
            tick_spacing: 60,
            hooks: Address::ZERO,
        };
        let mut pool = PoolState {
            reserve0: U256::from(10_000u64),
            reserve1: U256::from(10_000u64),
            liquidity: U256::from(10_000u64),
        };
        let mut accounting = FlashAccounting::default();
        donate(
            &key,
            &mut pool,
            U256::from(1_000u64),
            U256::from(500u64),
            &mut accounting,
        )
        .expect("donate");
        assert_eq!(pool.reserve0, U256::from(11_000u64));
        assert_eq!(pool.reserve1, U256::from(10_500u64));
        assert!(accounting
            .deltas
            .get(&token0)
            .map(|d| d.to_pool == U256::from(1_000u64))
            .unwrap_or(false));
    }
}
