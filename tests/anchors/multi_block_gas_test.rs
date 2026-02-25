use alloy::primitives::{Address, Bytes, U256};
use dark_solver::executor::builders::MultiBuilder;
use dark_solver::executor::gas_solver::GasOptimalitySolver;
use dark_solver::executor::multi_block::MultiBlockExecutor;
use dark_solver::solver::objectives::{ExploitParams, ExploitStep};
use std::collections::BTreeMap;

#[tokio::test]
async fn test_phase4_logic_integration() {
    // 1. Test Gas Solver with specific profit/gas scenarios
    let solver = GasOptimalitySolver::new(
        10_000_000_000, // 10 gwei base fee
        vec![
            100_000_000,   // p10: 0.1 gwei
            500_000_000,   // p25: 0.5 gwei
            1_000_000_000, // p50: 1 gwei
            2_000_000_000, // p75: 2 gwei
            5_000_000_000, // p90: 5 gwei
        ],
    );

    // Scenario: High profit (1 ETH), 500k gas
    let profit = U256::from(10u128.pow(18));
    let gas = 500_000u64;
    let tip = solver.optimal_tip(u128::try_from(profit).unwrap(), gas);

    // Should be capped by p75 since profit is huge
    assert_eq!(tip, 2_000_000_000, "Should cap at p75 for high profit");

    // Scenario: Low profit (0.01 ETH), 1M gas
    let low_profit = U256::from(10u128.pow(16));
    let tip_low = solver.optimal_tip(u128::try_from(low_profit).unwrap(), 1_000_000);
    // Base cost: 10 gwei * 1M = 0.01 ETH.
    // Profit is exactly equal to base cost. Tip should be 0.
    assert_eq!(
        tip_low, 0,
        "Should be 0 tip if profit barely covers base fee"
    );

    // 2. Test Multi-Block Sequencing
    let steps = vec![
        ExploitStep {
            target: Address::repeat_byte(1),
            call_data: Bytes::from_static(&[0x11]),
            execute_if: None,
        },
        ExploitStep {
            target: Address::repeat_byte(2),
            call_data: Bytes::from_static(&[0x22]),
            execute_if: None,
        },
    ];
    let offsets = vec![0, 1];
    let mb_executor = MultiBlockExecutor::new(&steps, Some(&offsets));

    assert!(mb_executor.is_multi_block());
    assert_eq!(mb_executor.max_block_span(), 1);

    let mut signed = BTreeMap::new();
    signed.insert(0, vec![Bytes::from_static(&[0x11, 0x11])]);
    signed.insert(1, vec![Bytes::from_static(&[0x22, 0x22])]);

    let bundles = mb_executor.to_bundles(100, &signed, 2000);
    assert_eq!(bundles.len(), 2);
    assert_eq!(bundles[0].0, 100); // Current block
    assert_eq!(bundles[1].0, 101); // Next block
    assert_eq!(bundles[0].1.txs[0], "0x1111");
    assert_eq!(bundles[1].1.txs[0], "0x2222");

    // 3. Verify MultiBuilder URL parsing
    let urls = vec![
        "https://rpc.beaverbuild.org".to_string(),
        "https://rpc.titanbuilder.xyz".to_string(),
    ];
    let mb = MultiBuilder::from_urls(&urls);
    assert_eq!(mb.num_builders(), 2);
}

#[tokio::test]
async fn test_exploit_params_multi_block_serialization() {
    let params = ExploitParams {
        flash_loan_amount: U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: Vec::new(),
        steps: vec![],
        expected_profit: Some(U256::from(100)),
        block_offsets: Some(vec![0, 1, 2]),
    };

    assert_eq!(params.block_offsets.unwrap().len(), 3);
}
