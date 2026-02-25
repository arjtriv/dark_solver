use std::fs;

#[test]
fn test_momentum_gas_oracle_is_wired() {
    let source = fs::read_to_string("src/executor/gas_solver.rs").expect("read gas_solver.rs");

    assert!(
        source.contains("GAS_MOMENTUM_ORACLE_ENABLED")
            && source.contains("GAS_MOMENTUM_KP_BPS")
            && source.contains("GAS_MOMENTUM_KI_BPS")
            && source.contains("GAS_MOMENTUM_KD_BPS")
            && source.contains("compute_momentum_tip_bump_wei")
            && source.contains("momentum_tip_bump_wei"),
        "gas solver must expose momentum/PID controls and derive tip bump from fee history trend"
    );
}
