use dark_solver::symbolic::opcodes::arithmetic::handle_arithmetic_opcode;
use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::{bv_from_u256, u256_from_bv};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestCaseError, TestRunner};
use revm::db::InMemoryDB;
use revm::primitives::{AccountInfo, Address, Bytecode, Bytes, ExecutionResult, TransactTo, U256};
use revm::Evm;
use z3::{Config as Z3Config, Context, Solver};

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

fn build_arithmetic_program(opcode: u8, push_order_words: &[U256]) -> Bytes {
    let mut code = Vec::with_capacity(push_order_words.len() * 33 + 16);
    for word in push_order_words {
        push32(&mut code, *word);
    }
    code.push(opcode);
    // Store result in memory[0..32] and return it.
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
    Bytes::from(code)
}

fn run_revm_opcode(opcode: u8, push_order_words: &[U256]) -> Result<U256, String> {
    let caller = Address::from([0xAA; 20]);
    let target = Address::from([0xBB; 20]);

    let bytecode_raw = build_arithmetic_program(opcode, push_order_words);
    let bytecode = Bytecode::new_raw(bytecode_raw);

    let mut db = InMemoryDB::default();
    let caller_info = AccountInfo {
        balance: U256::MAX,
        nonce: 1,
        code_hash: revm::primitives::KECCAK_EMPTY,
        code: None,
    };
    db.insert_account_info(caller, caller_info);

    let target_info = AccountInfo::new(U256::ZERO, 1, bytecode.hash_slow(), bytecode);
    db.insert_account_info(target, target_info);

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

    let result = evm
        .transact_commit()
        .map_err(|err| format!("revm execution error for opcode 0x{opcode:02x}: {err:?}"))?;

    let output = match result {
        ExecutionResult::Success { output, .. } => output.into_data(),
        other => {
            return Err(format!(
                "non-success result for opcode 0x{opcode:02x}: {other:?}"
            ));
        }
    };

    if output.len() < 32 {
        return Err(format!(
            "short output for opcode 0x{opcode:02x}: {} bytes",
            output.len()
        ));
    }

    let mut word = [0u8; 32];
    word.copy_from_slice(&output[..32]);
    Ok(U256::from_be_bytes(word))
}

fn run_symbolic_opcode(opcode: u8, push_order_words: &[U256]) -> Result<U256, String> {
    let cfg = Z3Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    for word in push_order_words {
        machine.sym_stack.push(bv_from_u256(&ctx, *word));
    }

    handle_arithmetic_opcode(&mut machine, opcode);
    let result = machine.sym_stack.pop();
    u256_from_bv(&result).ok_or_else(|| {
        format!(
            "symbolic result was not concrete for opcode 0x{opcode:02x}: {:?}",
            result
        )
    })
}

fn compare_opcode(opcode: u8, words: [U256; 3]) -> Result<(), String> {
    let arity = opcode_arity(opcode);
    let push_words = &words[..arity];
    let symbolic = run_symbolic_opcode(opcode, push_words)?;
    let concrete = run_revm_opcode(opcode, push_words)?;

    if symbolic != concrete {
        return Err(format!(
            "opcode 0x{opcode:02x} mismatch with push_order={push_words:?}: symbolic={symbolic:?} concrete={concrete:?}"
        ));
    }
    Ok(())
}

#[test]
fn test_arithmetic_opcode_soundness_smoke_all_opcodes() {
    let fixed_words = [U256::from(7u64), U256::from(3u64), U256::from(5u64)];
    for opcode in ARITHMETIC_OPCODES {
        compare_opcode(opcode, fixed_words)
            .unwrap_or_else(|msg| panic!("smoke mismatch for opcode 0x{opcode:02x}: {msg}"));
    }
}

#[test]
fn test_arithmetic_opcode_soundness_proptest_10000() {
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 10_000,
        ..ProptestConfig::default()
    });

    let opcode_strategy = prop::sample::select(ARITHMETIC_OPCODES.to_vec());
    let word_strategy = any::<[u8; 32]>().prop_map(U256::from_be_bytes);
    let strategy = (
        opcode_strategy,
        word_strategy.clone(),
        word_strategy.clone(),
        word_strategy,
    );

    let result = runner.run(&strategy, |(opcode, w0, w1, w2)| {
        compare_opcode(opcode, [w0, w1, w2]).map_err(TestCaseError::fail)
    });

    if let Err(err) = result {
        panic!("bit-level soundness proptest failed: {err}");
    }
}
