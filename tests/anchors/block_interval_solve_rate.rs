use std::fs;

#[test]
fn test_block_interval_solve_rate_gate() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for solve-rate gate");
    let verification_source = fs::read_to_string("src/solver/verification.rs")
        .expect("src/solver/verification.rs must be readable for solve-rate gate");

    assert!(
        main_source.contains("record_solve_cycle("),
        "solve cycles must be recorded for section8 solve-rate verification"
    );
    assert!(
        main_source.contains("\"primary\""),
        "primary solve cycles must be tracked"
    );
    assert!(
        main_source.contains("\"retry\""),
        "re-solve cycles must be tracked"
    );
    assert!(
        verification_source.contains("pub const SOLVE_BUDGET_MS: u64 = 1_800;"),
        "solve-rate verifier must use 1800ms budget"
    );
    assert!(
        verification_source.contains("pub const SOLVE_RATE_TARGET: f64 = 0.95;"),
        "solve-rate verifier must require 95% budget compliance"
    );
    assert!(
        verification_source.contains("sample.reentrancy_depth >= 3"),
        "solve-rate verifier must remain scoped to >=3 reentrancy depth"
    );
}
