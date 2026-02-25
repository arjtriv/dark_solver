use alloy::primitives::{keccak256, Address};
use revm::primitives::Bytes;

fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Canonical initializer signatures seen in upgradeable/proxy patterns.
pub fn known_initialization_selectors() -> Vec<[u8; 4]> {
    let mut selectors = vec![
        selector("initialize()"),
        selector("initialize(address)"),
        selector("initialize(address,address)"),
        selector("init()"),
        selector("init(address)"),
        selector("init(address,address)"),
    ];
    selectors.sort_unstable();
    selectors.dedup();
    selectors
}

pub fn selector_from_call_data(call_data: &Bytes) -> Option<[u8; 4]> {
    if call_data.len() < 4 {
        return None;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&call_data[..4]);
    Some(selector)
}

pub fn is_initialization_selector(selector: [u8; 4]) -> bool {
    known_initialization_selectors().contains(&selector)
}

/// Build minimal initializer payload variants:
/// - selector only
/// - selector + attacker address
/// - selector + attacker address + attacker address
pub fn build_initializer_payloads(selector: [u8; 4], attacker: Address) -> Vec<Bytes> {
    let mut payloads = Vec::with_capacity(3);
    payloads.push(Bytes::copy_from_slice(&selector));

    let mut address_word = [0u8; 32];
    address_word[12..32].copy_from_slice(attacker.as_slice());

    for repeats in [1usize, 2usize] {
        let mut payload = Vec::with_capacity(4 + (32 * repeats));
        payload.extend_from_slice(&selector);
        for _ in 0..repeats {
            payload.extend_from_slice(&address_word);
        }
        payloads.push(Bytes::from(payload));
    }

    payloads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_initialization_selector_set_contains_initialize_and_init() {
        let selectors = known_initialization_selectors();
        assert!(selectors.contains(&selector("initialize()")));
        assert!(selectors.contains(&selector("init()")));
        assert!(selectors.len() >= 6);
    }

    #[test]
    fn test_build_initializer_payloads_embed_attacker_address() {
        let attacker = Address::from([0x11; 20]);
        let sel = selector("initialize(address)");
        let payloads = build_initializer_payloads(sel, attacker);

        assert_eq!(payloads.len(), 3);
        assert_eq!(&payloads[0][..4], sel.as_slice());
        assert_eq!(&payloads[1][16..36], attacker.as_slice());
        assert_eq!(&payloads[2][16..36], attacker.as_slice());
        assert_eq!(&payloads[2][48..68], attacker.as_slice());
    }
}
