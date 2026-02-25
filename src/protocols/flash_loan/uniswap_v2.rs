use super::FlashLoanProvider;
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use anyhow::{anyhow, Result};

sol! {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data);
}

pub struct UniswapV2PairProvider {
    pub pair_address: Address,
    pub token0: Address,
    pub token1: Address,
    /// Used when callers pass `Address::ZERO` (engine-level "ETH") as the token.
    pub chain_weth: Address,
}

impl FlashLoanProvider for UniswapV2PairProvider {
    fn name(&self) -> &str {
        "Uniswap V2 Pair (flash swap)"
    }

    fn address(&self) -> Address {
        self.pair_address
    }

    fn fee_bps(&self) -> u32 {
        0
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

        let (amount0_out, amount1_out) = if token == self.token0 {
            (amount, U256::ZERO)
        } else if token == self.token1 {
            (U256::ZERO, amount)
        } else {
            return Err(anyhow!(
                "uniswap v2 pair token mismatch: token={:#x} not in ({:#x},{:#x})",
                token,
                self.token0,
                self.token1
            ));
        };

        // V2 callbacks fire only when `data` is non-empty. If the caller passes an empty
        // payload, force a 1-byte marker so the receiver gets control to repay.
        let data = if params.is_empty() {
            Bytes::from(vec![1u8])
        } else {
            params
        };

        let call = swapCall {
            amount0Out: amount0_out,
            amount1Out: amount1_out,
            to: receiver,
            data,
        };
        Ok(Bytes::from(call.abi_encode()))
    }
}
