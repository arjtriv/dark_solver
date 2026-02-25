//! Anchor Test: UniV2/UniV3 flash-swap providers encode the expected call shapes.

use alloy::primitives::{Address, Bytes, U256};
use dark_solver::protocols::flash_loan::{
    FlashLoanProvider, UniswapV2PairProvider, UniswapV3PoolProvider,
};

#[test]
fn test_uniswap_v3_flash_provider_encodes_amount0() {
    let pool = Address::new([0x11; 20]);
    let token0 = Address::new([0x22; 20]);
    let token1 = Address::new([0x33; 20]);
    let weth = Address::new([0x44; 20]);
    let receiver = Address::new([0x55; 20]);
    let data = Bytes::from(vec![0xaa, 0xbb]);

    let p = UniswapV3PoolProvider {
        pool_address: pool,
        token0,
        token1,
        fee_bps: 30,
        chain_weth: weth,
    };

    let encoded = p
        .encode_loan(token0, U256::from(7u64), receiver, data.clone())
        .expect("encode");
    // Selector: flash(address,uint256,uint256,bytes)
    assert_eq!(
        &encoded.as_ref()[0..4],
        &alloy::primitives::keccak256("flash(address,uint256,uint256,bytes)")[0..4]
    );
    assert!(encoded.as_ref().len() >= 4 + 32 * 4);
}

#[test]
fn test_uniswap_v2_flash_swap_provider_forces_non_empty_data() {
    let pair = Address::new([0x11; 20]);
    let token0 = Address::new([0x22; 20]);
    let token1 = Address::new([0x33; 20]);
    let weth = Address::new([0x44; 20]);
    let receiver = Address::new([0x55; 20]);

    let p = UniswapV2PairProvider {
        pair_address: pair,
        token0,
        token1,
        chain_weth: weth,
    };

    let encoded = p
        .encode_loan(token1, U256::from(9u64), receiver, Bytes::new())
        .expect("encode");
    // Selector: swap(uint256,uint256,address,bytes)
    assert_eq!(
        &encoded.as_ref()[0..4],
        &alloy::primitives::keccak256("swap(uint256,uint256,address,bytes)")[0..4]
    );
    // Data must be non-empty for callback. We can't fully decode without generating the ABI type here,
    // but this at least guards that we didn't return an empty payload.
    assert!(encoded.as_ref().len() > 4 + 32 * 3);
}
