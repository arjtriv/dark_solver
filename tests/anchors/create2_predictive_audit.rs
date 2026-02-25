//! Anchor Test: CREATE2 predictive address + init-code audit invariants.

use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::{bv_from_u256, u256_from_bv};
use revm::primitives::{keccak256, Address, U256};
use z3::{
    ast::{Ast, BV},
    Config, Context, Solver,
};

#[test]
fn test_predict_create2_address_matches_formula() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let machine = SymbolicMachine::new(&ctx, &solver, None);

    let deployer = Address::from_slice(&[0x11; 20]);
    let salt = U256::from(0xBEEF_u64);
    let init_code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
    let init_hash = U256::from_be_bytes(keccak256(init_code).0);

    let salt_bv = bv_from_u256(&ctx, salt);
    let init_hash_bv = bv_from_u256(&ctx, init_hash);
    let predicted = machine.predict_create2_address(deployer, &salt_bv, &init_hash_bv);

    let mut preimage = [0u8; 85];
    preimage[0] = 0xff;
    preimage[1..21].copy_from_slice(deployer.as_slice());
    preimage[21..53].copy_from_slice(&salt.to_be_bytes::<32>());
    preimage[53..85].copy_from_slice(&init_hash.to_be_bytes::<32>());

    let digest = keccak256(preimage);
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(&digest.0[12..32]);
    let expected = U256::from_be_bytes(padded);
    let expected_bv = bv_from_u256(&ctx, expected);

    solver.push();
    solver.assert(&predicted._eq(&expected_bv).not());
    assert_eq!(solver.check(), z3::SatResult::Unsat);
    solver.pop(1);
    assert_eq!(u256_from_bv(&predicted), Some(expected));
}

#[test]
fn test_create2_symbolic_prediction_zeroes_high_bits() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let machine = SymbolicMachine::new(&ctx, &solver, None);

    let deployer = Address::from_slice(&[0x22; 20]);
    let salt = BV::new_const(&ctx, "anchor_create2_salt_sym", 256);
    let init_hash = BV::new_const(&ctx, "anchor_create2_hash_sym", 256);
    let predicted = machine.predict_create2_address(deployer, &salt, &init_hash);

    let high_bits = predicted.extract(255, 160);
    solver.push();
    solver.assert(&high_bits._eq(&BV::from_u64(&ctx, 0, 96)).not());
    assert_eq!(solver.check(), z3::SatResult::Unsat);
    solver.pop(1);
}
