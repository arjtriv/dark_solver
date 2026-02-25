use super::FlashLoanProvider;
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use anyhow::Result;

sol! {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    );
}

pub struct AaveV3Provider {
    pub pool_address: Address,
}

impl FlashLoanProvider for AaveV3Provider {
    fn name(&self) -> &str {
        "Aave V3"
    }

    fn address(&self) -> Address {
        self.pool_address
    }

    fn fee_bps(&self) -> u32 {
        9 // 0.09%
    }

    fn encode_loan(
        &self,
        token: Address,
        amount: U256,
        receiver: Address,
        params: Bytes,
    ) -> Result<Bytes> {
        let assets = vec![token];
        let amounts = vec![amount];
        let modes = vec![U256::ZERO]; // 0 = None (Flash Loan)
        let on_behalf_of = receiver;
        let referral_code = 0;

        let call = flashLoanCall {
            receiverAddress: receiver,
            assets,
            amounts,
            interestRateModes: modes,
            onBehalfOf: on_behalf_of,
            params,
            referralCode: referral_code,
        };

        Ok(Bytes::from(call.abi_encode()))
    }
}
