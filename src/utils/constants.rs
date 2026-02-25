use alloy::primitives::U256;

/// Standard WAD (10^18)
pub const WAD_U256: U256 = U256::from_limbs([1000000000000000000, 0, 0, 0]);

/// Uniswap V2 Constants
pub const UNISWAP_V2_FEE_MULTIPLIER: u64 = 997;
pub const UNISWAP_V2_FEE_DENOMINATOR: u64 = 1000;

/// Economic Margin (0.001 ETH)
pub const MIN_PROFIT_MARGIN_WEI: u64 = 1_000_000_000_000_000;

/// EIP-1967 implementation storage slot (`keccak256("eip1967.proxy.implementation") - 1`).
pub const EIP1967_IMPL_SLOT: [u8; 32] = [
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9,
    0x8d, 0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38,
    0x2b, 0xbc,
];
