use super::FlashLoanProvider;
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use anyhow::Result;

sol! {
    function flashLoan(
        address recipient,
        address[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    );
}

pub struct BalancerProvider {
    pub vault_address: Address,
}

impl FlashLoanProvider for BalancerProvider {
    fn name(&self) -> &str {
        "Balancer Vault"
    }

    fn address(&self) -> Address {
        self.vault_address
    }

    fn fee_bps(&self) -> u32 {
        0 // 0%
    }

    fn encode_loan(
        &self,
        token: Address,
        amount: U256,
        receiver: Address,
        params: Bytes,
    ) -> Result<Bytes> {
        let tokens = vec![token];
        let amounts = vec![amount];

        let call = flashLoanCall {
            recipient: receiver,
            tokens,
            amounts,
            userData: params,
        };

        Ok(Bytes::from(call.abi_encode()))
    }
}
