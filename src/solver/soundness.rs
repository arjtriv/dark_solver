use dashmap::DashMap;
use revm::primitives::{Address, Bytes};
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoundnessLemma {
    pub contract: Address,
    pub selector: [u8; 4],
    pub reason: String,
}

static FALSE_POSITIVE_SELECTOR_BLOCKLIST: LazyLock<DashMap<(Address, [u8; 4]), SoundnessLemma>> =
    LazyLock::new(|| DashMap::with_capacity(512));

pub fn selector_from_call_data(call_data: &Bytes) -> Option<[u8; 4]> {
    if call_data.len() < 4 {
        return None;
    }
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&call_data[..4]);
    Some(selector)
}

pub fn register_false_positive_selector(
    contract: Address,
    call_data: &Bytes,
    reason: impl Into<String>,
) -> Option<SoundnessLemma> {
    let selector = selector_from_call_data(call_data)?;
    let lemma = SoundnessLemma {
        contract,
        selector,
        reason: reason.into(),
    };
    FALSE_POSITIVE_SELECTOR_BLOCKLIST.insert((contract, selector), lemma.clone());
    Some(lemma)
}

pub fn is_selector_blocked(contract: Address, call_data: &Bytes) -> bool {
    let Some(selector) = selector_from_call_data(call_data) else {
        return false;
    };
    FALSE_POSITIVE_SELECTOR_BLOCKLIST.contains_key(&(contract, selector))
}

pub fn clear_false_positive_lemmas() {
    FALSE_POSITIVE_SELECTOR_BLOCKLIST.clear();
}

pub fn lemma_count() -> usize {
    FALSE_POSITIVE_SELECTOR_BLOCKLIST.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_block_selector() {
        clear_false_positive_lemmas();
        let contract = Address::from([0x11; 20]);
        let call = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x00]);

        assert!(!is_selector_blocked(contract, &call));
        let lemma = register_false_positive_selector(contract, &call, "revert: bad calldata")
            .expect("selector must be parsed");
        assert_eq!(lemma.selector, [0xde, 0xad, 0xbe, 0xef]);
        assert!(is_selector_blocked(contract, &call));
        assert_eq!(lemma_count(), 1);
    }

    #[test]
    fn test_short_calldata_does_not_create_lemma() {
        clear_false_positive_lemmas();
        let contract = Address::from([0x22; 20]);
        let short = Bytes::from_static(&[0xab, 0xcd, 0xef]);
        assert!(register_false_positive_selector(contract, &short, "short").is_none());
        assert_eq!(lemma_count(), 0);
    }
}
