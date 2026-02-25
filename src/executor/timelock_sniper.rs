use alloy::primitives::Bytes;

pub fn should_snipe_execute(current_timestamp: u64, eta: u64) -> bool {
    current_timestamp >= eta
}

pub fn known_execute_payloads() -> Vec<Bytes> {
    let execute_tx =
        alloy::primitives::keccak256("executeTransaction(address,uint256,string,bytes,uint256)");
    let execute_u256 = alloy::primitives::keccak256("execute(uint256)");
    let execute_b32 = alloy::primitives::keccak256("execute(bytes32)");
    vec![
        Bytes::copy_from_slice(&execute_tx[0..4]),
        Bytes::copy_from_slice(&execute_u256[0..4]),
        Bytes::copy_from_slice(&execute_b32[0..4]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_snipe_execute_opens_at_eta() {
        assert!(should_snipe_execute(100, 100));
        assert!(!should_snipe_execute(99, 100));
    }

    #[test]
    fn test_known_execute_payloads_are_selectors() {
        let payloads = known_execute_payloads();
        assert_eq!(payloads.len(), 3);
        assert!(payloads.iter().all(|p| p.len() == 4));
    }
}
