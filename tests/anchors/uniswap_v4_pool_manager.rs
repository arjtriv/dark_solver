use dark_solver::protocols::uniswap_v4::{
    donate, modify_position, swap, FlashAccounting, HookAdjustments, PoolKey, PoolState,
    PositionAction, SwapParams,
};
use revm::primitives::{Address, U256};

#[test]
fn uniswap_v4_pool_manager_anchor() {
    let token0 = Address::from([0x10; 20]);
    let token1 = Address::from([0x20; 20]);
    let key = PoolKey {
        currency0: token0,
        currency1: token1,
        fee_pips: 3_000,
        tick_spacing: 60,
        hooks: Address::ZERO,
    };
    let mut pool = PoolState {
        reserve0: U256::from(1_000_000u64),
        reserve1: U256::from(1_000_000u64),
        liquidity: U256::from(1_000_000u64),
    };
    let mut accounting = FlashAccounting::default();

    let outcome = swap(
        &key,
        &mut pool,
        SwapParams {
            zero_for_one: true,
            amount_specified: U256::from(5_000u64),
            exact_input: true,
        },
        HookAdjustments::default(),
        &mut accounting,
    )
    .expect("swap should be modeled");
    assert!(outcome.amount_out > U256::ZERO);

    let add = modify_position(
        &key,
        &mut pool,
        PositionAction::Add {
            amount0_desired: U256::from(10_000u64),
            amount1_desired: U256::from(10_000u64),
        },
        &mut accounting,
    )
    .expect("liquidity add");
    assert!(add.liquidity_delta > U256::ZERO);

    donate(
        &key,
        &mut pool,
        U256::from(100u64),
        U256::from(200u64),
        &mut accounting,
    )
    .expect("donate must be modeled");
    assert!(
        accounting.deltas.contains_key(&token0) && accounting.deltas.contains_key(&token1),
        "flash accounting must track both currencies"
    );
}
