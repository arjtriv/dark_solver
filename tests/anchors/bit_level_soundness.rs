//! Anchor Test: arithmetic opcode symbolic semantics must match concrete REVM execution.

use dark_solver::symbolic::opcodes::arithmetic::handle_arithmetic_opcode;
use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::{bv_from_u256, u256_from_bv};
use revm::db::InMemoryDB;
use revm::primitives::{AccountInfo, Address, Bytecode, Bytes, ExecutionResult, TransactTo, U256};
use revm::Evm;
use z3::{Config, Context, Solver};

const ARITHMETIC_OPCODES: [u8; 25] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
];

fn opcode_arity(opcode: u8) -> usize {
    match opcode {
        0x08 | 0x09 => 3,
        0x15 | 0x19 => 1,
        _ => 2,
    }
}

fn push32(code: &mut Vec<u8>, word: U256) {
    code.push(0x7f);
    code.extend_from_slice(&word.to_be_bytes::<32>());
}

fn build_program(opcode: u8, words: &[U256]) -> Bytes {
    let mut code = Vec::new();
    for word in words {
        push32(&mut code, *word);
    }
    code.push(opcode);
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
    Bytes::from(code)
}

fn run_revm(opcode: u8, words: &[U256]) -> U256 {
    let caller = Address::from([0xAA; 20]);
    let target = Address::from([0xBB; 20]);
    let bytecode = Bytecode::new_raw(build_program(opcode, words));

    let mut db = InMemoryDB::default();
    db.insert_account_info(
        caller,
        AccountInfo {
            balance: U256::MAX,
            nonce: 1,
            code_hash: revm::primitives::KECCAK_EMPTY,
            code: None,
        },
    );
    db.insert_account_info(
        target,
        AccountInfo::new(U256::ZERO, 1, bytecode.hash_slow(), bytecode),
    );

    let mut evm = Evm::builder()
        .with_db(&mut db)
        .modify_tx_env(|tx| {
            tx.caller = caller;
            tx.transact_to = TransactTo::Call(target);
            tx.data = Bytes::new();
            tx.value = U256::ZERO;
            tx.gas_limit = 1_000_000;
        })
        .build();

    let output = match evm.transact_commit().expect("revm tx must execute") {
        ExecutionResult::Success { output, .. } => output.into_data(),
        other => panic!("opcode 0x{opcode:02x} reverted in anchor: {other:?}"),
    };
    let mut word = [0u8; 32];
    word.copy_from_slice(&output[..32]);
    U256::from_be_bytes(word)
}

fn run_symbolic(opcode: u8, words: &[U256]) -> U256 {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);
    for word in words {
        machine.sym_stack.push(bv_from_u256(&ctx, *word));
    }
    handle_arithmetic_opcode(&mut machine, opcode);
    let result = machine.sym_stack.pop();
    u256_from_bv(&result).expect("anchor result must be concrete")
}

#[test]
fn test_arithmetic_soundness_anchor_all_opcodes() {
    let words = [
        U256::from(0x1234u64),
        U256::from(0x55u64),
        U256::from(0x77u64),
    ];
    for opcode in ARITHMETIC_OPCODES {
        let arity = opcode_arity(opcode);
        let args = &words[..arity];
        let symbolic = run_symbolic(opcode, args);
        let concrete = run_revm(opcode, args);
        assert_eq!(
            symbolic, concrete,
            "anchor mismatch opcode=0x{opcode:02x}, args={args:?}"
        );
    }
}
