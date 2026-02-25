use std::fs;

#[test]
fn test_targeted_l2_opcode_soundness_is_wired() {
    let calls_source = fs::read_to_string("src/symbolic/opcodes/calls.rs")
        .expect("src/symbolic/opcodes/calls.rs must be readable");
    let solver_source = fs::read_to_string("src/tactics/objectives/objectives_tail_and_tests.rs")
        .expect("src/tactics/objectives/objectives_tail_and_tests.rs must be readable");

    assert!(
        calls_source.contains("OPSTACK_GAS_PRICE_ORACLE_BYTES")
            && calls_source.contains("getL1Fee(bytes)")
            && calls_source.contains("OPSTACK_L1_FEE_OVERHEAD_WEI")
            && calls_source.contains("OPSTACK_L1_FEE_PER_BYTE_WEI"),
        "calls.rs must model OP-Stack GasPriceOracle.getL1Fee(bytes) with tunable fee envelope"
    );
    assert!(
        solver_source.contains("SYMBOLIC_BLOCK_NUMBER")
            && solver_source.contains("SYMBOLIC_BLOCK_TIMESTAMP")
            && solver_source.contains("SYMBOLIC_BASEFEE_WEI")
            && solver_source.contains("SYMBOLIC_GASPRICE_WEI")
            && solver_source.contains("env.cfg.chain_id")
            && solver_source.contains("env.block.basefee")
            && solver_source.contains("env.tx.gas_price"),
        "symbolic EVM env must set chain_id/basefee/gas_price and non-zero block fields to avoid L2 drift"
    );
}
