use std::fs;

#[test]
fn test_concrete_fuzz_fast_lane_is_wired_and_budgeted() {
    let main = fs::read_to_string("src/main.rs").expect("src/main.rs must be readable");
    assert!(
        main.contains("CONCRETE_FUZZ_BUDGET_MS"),
        "main must read CONCRETE_FUZZ_BUDGET_MS for fuzz fast-lane budget"
    );
    assert!(
        main.contains("try_concrete_fuzz_fast_lane"),
        "main must attempt concrete fuzz fast lane before Z3 when enabled"
    );
    assert!(
        main.contains("[FUZZ] Fast lane concrete fuzz hit"),
        "main must emit a concrete fuzz hit signal when it triggers"
    );
}
