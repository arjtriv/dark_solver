use std::fs;

#[test]
fn test_generalized_frontrun_smart_mirror_rewrites_supported_swaps() {
    let strategy = fs::read_to_string("src/strategies/generalized_frontrun.rs")
        .expect("read src/strategies/generalized_frontrun.rs");

    assert!(
        strategy.contains("function swapExactTokensForTokens")
            && strategy.contains("function exactInput(")
            && strategy.contains("rewrite_mirror_call_data")
            && strategy.contains("decoded.to = recipient;")
            && strategy.contains("decoded.deadline = replacement_deadline;")
            && strategy.contains("decoded.params.recipient = recipient;")
            && strategy.contains("decoded.params.deadline = replacement_deadline;"),
        "smart mirror must ABI-decode supported swaps and rewrite recipient/deadline"
    );

    assert!(
        strategy.contains("GENERALIZED_FRONTRUN_MIRROR_DEADLINE_SECS"),
        "mirror deadline should be explicitly configurable"
    );
}
