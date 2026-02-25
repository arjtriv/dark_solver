use dark_solver::symbolic::opcodes::arithmetic::handle_arithmetic_opcode;
use dark_solver::symbolic::state::SymbolicMachine;
use z3::ast::{Ast, BV};
use z3::{Config, Context, SatResult, Solver};

fn assert_opcode_zero_divisor_yields_zero(opcode: u8) {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let numerator = BV::new_const(&ctx, format!("numerator_{opcode}"), 256);
    let zero = BV::from_u64(&ctx, 0, 256);

    machine.sym_stack.push(zero.clone());
    machine.sym_stack.push(numerator);
    handle_arithmetic_opcode(&mut machine, opcode);

    let result = machine.sym_stack.pop();
    solver.assert(&result._eq(&zero).not());
    assert_eq!(solver.check(), SatResult::Unsat);
}

fn assert_opcode_zero_modulus_yields_zero(opcode: u8) {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let a = BV::new_const(&ctx, format!("a_{opcode}"), 256);
    let b = BV::new_const(&ctx, format!("b_{opcode}"), 256);
    let zero = BV::from_u64(&ctx, 0, 256);

    // Stack order for these opcodes is: top=a, next=b, next=m
    machine.sym_stack.push(zero.clone());
    machine.sym_stack.push(b);
    machine.sym_stack.push(a);
    handle_arithmetic_opcode(&mut machine, opcode);

    let result = machine.sym_stack.pop();
    solver.assert(&result._eq(&zero).not());
    assert_eq!(solver.check(), SatResult::Unsat);
}

#[test]
fn test_division_family_zero_divisor_returns_zero() {
    for opcode in [0x04u8, 0x05, 0x06, 0x07] {
        assert_opcode_zero_divisor_yields_zero(opcode);
    }
}

#[test]
fn test_mod_family_zero_modulus_returns_zero() {
    for opcode in [0x08u8, 0x09] {
        assert_opcode_zero_modulus_yields_zero(opcode);
    }
}
