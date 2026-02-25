use alloy::primitives::{Address, Bytes};
use dark_solver::executor::payload_hardening::harden_exploit_params;
use dark_solver::solver::objectives::{ExploitParams, ExploitStep};
use dark_solver::solver::setup::{ATTACKER, TARGET};
use std::fs;

fn abi_encode_address_word(addr: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(addr.0.as_slice());
    word
}

#[test]
fn test_payload_hardening_resolves_attacker_and_target_sentinels_in_calldata_words() {
    let real_target = Address::from([0x11; 20]);
    let real_attacker = Address::from([0x22; 20]);

    // selector + two ABI-encoded address args
    let mut data = Vec::new();
    data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    data.extend_from_slice(&abi_encode_address_word(TARGET));
    data.extend_from_slice(&abi_encode_address_word(ATTACKER));
    let call_data = Bytes::from(data);

    let params = ExploitParams {
        flash_loan_amount: alloy::primitives::U256::ZERO,
        flash_loan_token: Address::ZERO,
        flash_loan_provider: Address::ZERO,
        flash_loan_legs: vec![],
        steps: vec![ExploitStep {
            target: TARGET,
            call_data,
            execute_if: None,
        }],
        expected_profit: None,
        block_offsets: None,
    };

    let hardened = harden_exploit_params(params, real_target, real_attacker);
    let step = &hardened.steps[0];
    assert_eq!(step.target, real_target);

    let bytes = step.call_data.as_ref();
    assert_eq!(&bytes[4 + 12..4 + 32], real_target.0.as_slice());
    assert_eq!(&bytes[4 + 32 + 12..4 + 64], real_attacker.0.as_slice());

    let exec_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for payload hardening audit");
    assert!(
        exec_source.contains("payload_hardening::harden_exploit_params"),
        "executor must harden payloads before replay/signing"
    );
}
