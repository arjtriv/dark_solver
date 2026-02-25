use alloy::primitives::{Address, Bytes};
use dark_solver::executor::gas_solver::{opstack_l1_calldata_gas, opstack_l1_calldata_gas_chunks};
use dark_solver::executor::multi_block::MultiBlockExecutor;
use dark_solver::solver::objectives::ExploitStep;

#[test]
fn test_opstack_calldata_gas_chunk_streaming_matches_concat() {
    let chunks = [
        vec![0x00, 0x11, 0x00, 0x22],
        vec![0xaa, 0xbb, 0x00],
        vec![0x00, 0x00, 0xff],
    ];
    let concatenated = chunks.concat();
    let concat_gas = opstack_l1_calldata_gas(&concatenated);
    let (chunk_gas, total_len) =
        opstack_l1_calldata_gas_chunks(chunks.iter().map(|c| c.as_slice()));

    assert_eq!(total_len, concatenated.len());
    assert_eq!(chunk_gas, concat_gas);
}

#[test]
fn test_multiblock_executor_uses_borrowed_steps_and_offsets() {
    let steps = vec![
        ExploitStep {
            target: Address::repeat_byte(0x01),
            call_data: Bytes::from_static(&[0xaa]),
            execute_if: None,
        },
        ExploitStep {
            target: Address::repeat_byte(0x02),
            call_data: Bytes::from_static(&[0xbb]),
            execute_if: None,
        },
    ];
    let offsets = vec![0u64, 1u64];

    let executor = MultiBlockExecutor::new(&steps, Some(&offsets));
    let grouped = executor.grouped_steps();

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped[&0][0].step.target, steps[0].target);
    assert_eq!(grouped[&1][0].step.target, steps[1].target);
}
