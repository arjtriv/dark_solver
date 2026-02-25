use super::FlashLoanProvider;
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use anyhow::{anyhow, Result};

sol! {
    function flash(address recipient, uint256 amount0, uint256 amount1, bytes calldata data);
}

pub struct UniswapV3PoolProvider {
    pub pool_address: Address,
    pub token0: Address,
    pub token1: Address,
    pub fee_bps: u32,
    /// Used when callers pass `Address::ZERO` (engine-level "ETH") as the token.
    pub chain_weth: Address,
}

impl FlashLoanProvider for UniswapV3PoolProvider {
    fn name(&self) -> &str {
        "Uniswap V3 Pool (flash)"
    }

    fn address(&self) -> Address {
        self.pool_address
    }

    fn fee_bps(&self) -> u32 {
        self.fee_bps
    }

    fn encode_loan(
        &self,
        token: Address,
        amount: U256,
        receiver: Address,
        params: Bytes,
    ) -> Result<Bytes> {
        let token = if token == Address::ZERO {
            self.chain_weth
        } else {
            token
        };

        let (amount0, amount1) = if token == self.token0 {
            (amount, U256::ZERO)
        } else if token == self.token1 {
            (U256::ZERO, amount)
        } else {
            return Err(anyhow!(
                "uniswap v3 pool token mismatch: token={:#x} not in ({:#x},{:#x})",
                token,
                self.token0,
                self.token1
            ));
        };

        let call = flashCall {
            recipient: receiver,
            amount0,
            amount1,
            data: params,
        };

        Ok(Bytes::from(call.abi_encode()))
    }
}
