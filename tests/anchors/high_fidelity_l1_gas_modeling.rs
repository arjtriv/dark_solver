//! Anchor: OP-stack L1 fee modeling must use oracle parameters (overhead/scalar/decimals),
//! not a linear `len * l1BaseFee` approximation.

use std::fs;

#[test]
fn test_high_fidelity_l1_gas_modeling_is_wired() {
    let gas_solver = fs::read_to_string("src/executor/gas_solver.rs")
        .expect("src/executor/gas_solver.rs must be readable for L1 fee modeling anchor");
    let executor = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for L1 fee modeling anchor");

    assert!(
        gas_solver.contains("overhead()")
            && gas_solver.contains("scalar()")
            && gas_solver.contains("decimals()"),
        "gas solver must fetch OP-stack oracle parameters (overhead/scalar/decimals)"
    );
    assert!(
        gas_solver.contains("opstack_l1_fee_wei_from_calldata")
            && gas_solver.contains("l1_gas_used")
            && gas_solver.contains("10u128.pow"),
        "gas solver must compute L1 fee via (gasUsed+overhead)*l1BaseFee*scalar/10^decimals"
    );
    assert!(
        executor.contains("estimate_opstack_l1_fee_wei_exact_cached")
            && !executor.contains("estimate_opstack_l1_data_fee_wei_cached("),
        "executor must use the high-fidelity OP-stack L1 fee estimator"
    );
}
