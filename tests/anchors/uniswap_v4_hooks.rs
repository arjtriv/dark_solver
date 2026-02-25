use dark_solver::protocols::uniswap_v4::{
    hook_selectors, is_hook_callback_selector, modeled_hook_return_words,
};
use std::collections::HashSet;

#[test]
fn test_hook_selector_catalog_is_unique() {
    let selectors = hook_selectors();
    let uniq: HashSet<u32> = selectors.iter().copied().collect();
    assert_eq!(
        selectors.len(),
        uniq.len(),
        "Hook selector catalog must not contain collisions."
    );
}

#[test]
fn test_hook_selector_roundtrip_recognition() {
    for selector in hook_selectors() {
        assert!(
            is_hook_callback_selector(selector),
            "Known hook selector should be recognized."
        );
    }
    assert!(
        !is_hook_callback_selector(0x0902f1ac),
        "UniswapV2 getReserves selector must not be classified as a UniV4 hook callback."
    );
}

#[test]
fn test_hook_return_words_are_bounded() {
    for selector in hook_selectors() {
        let words = modeled_hook_return_words(selector);
        assert!(
            (1..=3).contains(&words),
            "Modeled hook return payload must stay within bounded symbolic envelope."
        );
    }
}
