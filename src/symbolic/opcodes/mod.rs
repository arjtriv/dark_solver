#[macro_use]
pub mod op_macros;
pub mod arithmetic;
pub mod calls;
pub mod context;
pub mod control;
pub mod memory;
pub mod stack;

use crate::symbolic::state::SymbolicMachine;
use revm::interpreter::Interpreter;
use revm::{Database, EvmContext};

pub fn dispatch<'ctx, DB: Database>(
    machine: &mut SymbolicMachine<'ctx>,
    interpreter: &mut Interpreter,
    context: &mut EvmContext<DB>,
    opcode: u8,
) {
    match opcode {
        // Arithmetic: ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD, EXP, SIGNEXTEND
        // Comparison: LT, GT, SLT, SGT, EQ, ISZERO
        // Bitwise: AND, OR, XOR, NOT, BYTE, SHL, SHR, SAR
        0x01..=0x0b | 0x10..=0x1d => {
            arithmetic::handle_arithmetic(machine, interpreter, opcode);
        }
        // Memory: SHA3, MLOAD, MSTORE, MSTORE8, SLOAD, SSTORE, MSIZE
        0x20 | 0x51..=0x53 | 0x54 | 0x55 | 0x59 => {
            memory::handle_memory(machine, interpreter, context, opcode);
        }
        // Control: STOP, JUMP, JUMPI, PC, GAS, JUMPDEST, POP, RETURNDATASIZE, RETURNDATACOPY
        // LOG0-LOG4, INVALID, SELFDESTRUCT
        0x00
        | 0x56
        | 0x57
        | 0x58
        | 0x5a
        | 0x5b
        | 0x50
        | 0x3d
        | 0x3e
        | 0xa0..=0xa4
        | 0xfe
        | 0xff => {
            control::handle_control(machine, interpreter, context, opcode);
        }
        // Context: ADDRESS, BALANCE, ORIGIN, CALLER, CALLVALUE
        // CALLDATASIZE, CALLDATACOPY, CODESIZE, CODECOPY, GASPRICE
        // EXTCODESIZE, EXTCODECOPY, EXTCODEHASH, BLOCKHASH
        // Block: COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT, CHAINID, SELFBALANCE, BASEFEE
        0x30..=0x34 | 0x38..=0x3c | 0x3f | 0x40..=0x48 => {
            context::handle_context(machine, interpreter, context, opcode);
        }
        // Calls: CALLDATALOAD, CALLDATASIZE, CALLDATACOPY
        // CALL, CALLCODE, DELEGATECALL, STATICCALL, RETURN, REVERT
        // CREATE, CREATE2
        0x35..=0x37 | 0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa | 0xf3 | 0xfd => {
            calls::handle_calls(machine, interpreter, context, opcode);
        }
        // Stack: DUP1-DUP16, SWAP1-SWAP16
        0x80..=0x9f => {
            stack::handle_stack(machine, opcode);
        }
        _ => {}
    }
}
