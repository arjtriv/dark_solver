use crate::symbolic::state::SymbolicMachine;
use revm::interpreter::Interpreter;
use z3::ast::Ast;

pub fn handle_arithmetic<'ctx>(
    machine: &mut SymbolicMachine<'ctx>,
    _interpreter: &Interpreter,
    opcode: u8,
) {
    handle_arithmetic_opcode(machine, opcode);
}

pub fn handle_arithmetic_opcode<'ctx>(machine: &mut SymbolicMachine<'ctx>, opcode: u8) {
    match opcode {
        0x01 => {
            binary_op!(machine, bvadd);
        }
        0x02 => {
            binary_op!(machine, bvmul);
        }
        0x03 => {
            binary_op!(machine, bvsub);
        }
        0x04 => {
            binary_op!(machine, crate::symbolic::utils::math::safe_div);
        }
        0x05 => {
            binary_op!(machine, crate::symbolic::utils::math::safe_sdiv);
        }
        0x06 => {
            binary_op!(machine, crate::symbolic::utils::math::safe_rem);
        }
        0x07 => {
            binary_op!(machine, crate::symbolic::utils::math::safe_srem);
        }
        0x08 => {
            let a = machine.sym_stack.pop();
            let b = machine.sym_stack.pop();
            let m = machine.sym_stack.pop();
            let a_512 = crate::symbolic::utils::math::extend_to_512(machine.context, &a);
            let b_512 = crate::symbolic::utils::math::extend_to_512(machine.context, &b);
            let m_512 = crate::symbolic::utils::math::extend_to_512(machine.context, &m);

            let sum = a_512.bvadd(&b_512);
            // Fix: Wrap potential division-by-zero
            let safe_rem = crate::symbolic::utils::math::safe_rem(&sum, &m_512);
            let res_256 = safe_rem.extract(255, 0);

            machine.sym_stack.push(res_256);
        }
        0x09 => {
            let a = machine.sym_stack.pop();
            let b = machine.sym_stack.pop();
            let m = machine.sym_stack.pop();

            let a_512 = crate::symbolic::utils::math::extend_to_512(machine.context, &a);
            let b_512 = crate::symbolic::utils::math::extend_to_512(machine.context, &b);
            let m_512 = crate::symbolic::utils::math::extend_to_512(machine.context, &m);

            let prod = a_512.bvmul(&b_512);
            let safe_rem = crate::symbolic::utils::math::safe_rem(&prod, &m_512);
            let res_256 = safe_rem.extract(255, 0);
            machine.sym_stack.push(res_256);
        }
        0x0a => {
            let base = machine.sym_stack.pop();
            let exponent = machine.sym_stack.pop();
            machine
                .sym_stack
                .push(crate::symbolic::utils::math::symbolic_exp(
                    machine.context,
                    &base,
                    &exponent,
                ));
        }
        // SIGNEXTEND (0x0b)
        0x0b => {
            let b = machine.sym_stack.pop();
            let x = machine.sym_stack.pop();
            machine
                .sym_stack
                .push(crate::symbolic::utils::math::symbolic_signextend(
                    machine.context,
                    &b,
                    &x,
                ));
        }
        // EQ (0x14)
        // EQ (0x14)
        0x14 => {
            comparison_op!(machine, _eq);
        }
        0x15 => {
            let a = machine.sym_stack.pop();
            let is_zero = a._eq(&crate::symbolic::utils::math::zero(machine.context));
            machine.sym_stack.push(is_zero.ite(
                &crate::symbolic::utils::math::one(machine.context),
                &crate::symbolic::utils::math::zero(machine.context),
            ));
        }
        0x10 => {
            comparison_op!(machine, bvult);
        }
        0x11 => {
            comparison_op!(machine, bvugt);
        }
        0x12 => {
            comparison_op!(machine, bvslt);
        }
        0x13 => {
            comparison_op!(machine, bvsgt);
        }
        // SHR, SHL, SAR (0x1c, 0x1b, 0x1d)
        0x1c => {
            let shift = machine.sym_stack.pop();
            let val = machine.sym_stack.pop();
            machine.sym_stack.push(val.bvlshr(&shift));
        }
        0x1b => {
            let shift = machine.sym_stack.pop();
            let val = machine.sym_stack.pop();
            machine.sym_stack.push(val.bvshl(&shift));
        }
        0x1d => {
            let shift = machine.sym_stack.pop();
            let val = machine.sym_stack.pop();
            machine.sym_stack.push(val.bvashr(&shift));
        }
        // AND, OR, XOR, NOT (0x16, 0x17, 0x18, 0x19)
        0x16 => {
            binary_op!(machine, bvand);
        }
        0x17 => {
            binary_op!(machine, bvor);
        }
        0x18 => {
            binary_op!(machine, bvxor);
        }
        0x19 => {
            unary_op!(machine, bvnot);
        }
        // BYTE (0x1a)
        0x1a => {
            let i = machine.sym_stack.pop();
            let val = machine.sym_stack.pop();
            machine
                .sym_stack
                .push(crate::symbolic::utils::math::symbolic_byte(
                    machine.context,
                    &i,
                    &val,
                ));
        }
        _ => {}
    }
}
