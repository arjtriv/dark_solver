use crate::symbolic::state::SymbolicMachine;
use crate::symbolic::{
    error::{apply_opcode_error, lift_option, SymbolicErrorKind},
    z3_ext::u256_from_bv,
};
use revm::interpreter::Interpreter;
use revm::primitives::{Address, U256};
use revm::{Database, EvmContext};
use z3::ast::{Ast, BV};

fn enforce_clean_address_word<'ctx>(machine: &mut SymbolicMachine<'ctx>, addr_word: &BV<'ctx>) {
    let cleaned = crate::symbolic::utils::math::clean_address_word(addr_word);
    machine.solver.assert(&addr_word._eq(&cleaned));
}

pub fn handle_context<'ctx, DB: Database>(
    machine: &mut SymbolicMachine<'ctx>,
    interpreter: &mut Interpreter,
    _context: &mut EvmContext<DB>,
    opcode: u8,
) {
    match opcode {
        // BALANCE (0x31)
        0x31 => {
            let addr_bv = machine.sym_stack.pop();
            enforce_clean_address_word(machine, &addr_bv);

            // Try concrete resolution first (from concrete interpreter stack),
            // then fall back to symbolic BV extraction.
            let addr_opt = interpreter
                .stack()
                .peek(0)
                .ok()
                .map(|u| Address::from_slice(&u.to_be_bytes::<32>()[12..32]))
                .or_else(|| crate::symbolic::z3_ext::bv_to_address(&addr_bv));

            let z3_val = addr_opt
                .and_then(|addr| machine.balance_overrides.get(&addr).cloned())
                .unwrap_or_else(|| BV::from_u64(machine.context, 0, 256));

            machine.sym_stack.push(z3_val);
        }
        // SELFBALANCE (0x47)
        0x47 => {
            let addr = interpreter.contract.target_address;
            let z3_val = if let Some(bal) = machine.balance_overrides.get(&addr) {
                bal.clone()
            } else {
                crate::symbolic::utils::math::zero(machine.context)
            };
            machine.sym_stack.push(z3_val);
        }
        // CALLVALUE (0x34)
        0x34 => {
            if let Some(ref sym_val) = machine.call_value {
                machine.sym_stack.push(sym_val.clone());
            } else {
                machine
                    .sym_stack
                    .push(crate::symbolic::utils::math::zero(machine.context));
            }
        }
        // CALLER (0x33) — msg.sender (immediate caller), NOT tx.origin
        0x33 => {
            let caller = if machine.frames.is_empty() {
                machine.effective_top_level_msg_sender(interpreter.contract.caller)
            } else {
                interpreter.contract.caller
            };
            let mut bytes = [0u8; 32];
            bytes[12..32].copy_from_slice(caller.as_slice());
            let caller_u256 = U256::from_be_bytes(bytes);
            let z3_val = crate::symbolic::z3_ext::bv_from_u256(machine.context, caller_u256);
            machine.sym_stack.push(z3_val);
        }
        // ADDRESS (0x30)
        0x30 => {
            let addr = interpreter.contract.target_address;
            let mut bytes = [0u8; 32];
            bytes[12..32].copy_from_slice(addr.as_slice());
            let addr_u256 = U256::from_be_bytes(bytes);
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    addr_u256,
                ));
        }
        // ORIGIN (0x32)
        0x32 => {
            let origin = machine.effective_tx_origin(_context.env.tx.caller);
            let mut bytes = [0u8; 32];
            bytes[12..32].copy_from_slice(origin.as_slice());
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from_be_bytes(bytes),
                ));
        }
        // GASPRICE (0x3a)
        0x3a => {
            let gp = _context.env.tx.gas_price;
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(gp),
                ));
        }
        // COINBASE (0x41)
        0x41 => {
            let cb = _context.env.block.coinbase;
            let mut bytes = [0u8; 32];
            bytes[12..32].copy_from_slice(cb.as_slice());
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from_be_bytes(bytes),
                ));
        }
        // TIMESTAMP (0x42)
        0x42 => {
            let ts = _context.env.block.timestamp;
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(machine.context, ts));
        }
        // NUMBER (0x43)
        0x43 => {
            let num = _context.env.block.number;
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(machine.context, num));
        }
        // PREVRANDAO / DIFFICULTY (0x44)
        0x44 => {
            let diff = _context.env.block.prevrandao.unwrap_or_default();
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from_be_bytes(diff.0),
                ));
        }
        // GASLIMIT (0x45)
        0x45 => {
            let gl = _context.env.block.gas_limit;
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(machine.context, gl));
        }
        // CHAINID (0x46)
        0x46 => {
            let cid = _context.env.cfg.chain_id;
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(cid),
                ));
        }
        // BASEFEE (0x48)
        0x48 => {
            let bf = _context.env.block.basefee;
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(machine.context, bf));
        }
        // EXTCODESIZE (0x3B)
        0x3B => {
            let addr_bv = machine.sym_stack.pop();
            enforce_clean_address_word(machine, &addr_bv);
            if let Some(addr_word) = u256_from_bv(&addr_bv) {
                let concrete_addr = Address::from_word(addr_word.into());
                if machine.destroyed_contracts.contains(&concrete_addr) {
                    machine
                        .sym_stack
                        .push(crate::symbolic::utils::math::zero(machine.context));
                    return;
                }
            }
            let addr_str = crate::symbolic::z3_ext::u256_from_bv(&addr_bv)
                .map(|v| format!("{:x}", v))
                .unwrap_or_else(|| format!("sym_{}", machine.tx_id));
            let name = format!("ext_code_size_{}", addr_str);
            let size = BV::new_const(machine.context, name.as_str(), 256);
            machine.sym_stack.push(size);
        }
        // EXTCODEHASH (0x3F)
        0x3F => {
            let addr_bv = machine.sym_stack.pop();
            enforce_clean_address_word(machine, &addr_bv);
            if let Some(addr_word) = u256_from_bv(&addr_bv) {
                let concrete_addr = Address::from_word(addr_word.into());
                if let Some(forced_hash) = machine.ext_code_hash_overrides.get(&concrete_addr) {
                    machine.sym_stack.push(forced_hash.clone());
                    return;
                }
                if machine.destroyed_contracts.contains(&concrete_addr) {
                    machine
                        .sym_stack
                        .push(crate::symbolic::utils::math::zero(machine.context));
                    return;
                }
            }
            let addr_str = crate::symbolic::z3_ext::u256_from_bv(&addr_bv)
                .map(|v| format!("{:x}", v))
                .unwrap_or_else(|| format!("sym_{}", machine.tx_id));
            let name = format!("ext_code_hash_{}", addr_str);
            let hash = BV::new_const(machine.context, name.as_str(), 256);
            machine.sym_stack.push(hash);
        }
        // CODESIZE (0x38)
        0x38 => {
            let bytecode_bytes = interpreter.contract.bytecode.original_byte_slice();
            let size = bytecode_bytes.len();
            machine
                .sym_stack
                .push(crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(size),
                ));
        }
        // CODECOPY (0x39)
        0x39 => {
            let dest_off = machine.sym_stack.pop();
            let code_off = machine.sym_stack.pop();
            let len = machine.sym_stack.pop();

            let bytecode_bytes = interpreter.contract.bytecode.original_byte_slice();
            let pc = interpreter.program_counter();
            let offset_opt = u256_from_bv(&code_off).and_then(|v| v.try_into().ok());
            let o_u: usize = match lift_option(
                machine,
                pc,
                opcode,
                SymbolicErrorKind::NonConcreteCodeOffset,
                offset_opt,
                "CODECOPY requires a concrete code offset",
            ) {
                Ok(offset) => offset,
                Err(err) => {
                    apply_opcode_error(machine, interpreter, err);
                    return;
                }
            };
            let l_u = crate::symbolic::utils::math::bounded_len(&len, 1024);

            for i in 0..l_u {
                let byte = if o_u + i < bytecode_bytes.len() {
                    BV::from_u64(machine.context, bytecode_bytes[o_u + i] as u64, 8)
                } else {
                    BV::from_u64(machine.context, 0, 8)
                };
                let idx = dest_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));
                machine.write_byte(idx, byte);
            }
        }
        // EXTCODECOPY (0x3C)
        0x3C => {
            let addr = machine.sym_stack.pop();
            enforce_clean_address_word(machine, &addr);
            let dest_off = machine.sym_stack.pop();
            let _code_off = machine.sym_stack.pop();
            let len = machine.sym_stack.pop();

            let l_u = crate::symbolic::utils::math::bounded_len(&len, 1024);
            let is_destroyed = u256_from_bv(&addr)
                .map(|word| Address::from_word(word.into()))
                .map(|concrete_addr| machine.destroyed_contracts.contains(&concrete_addr))
                .unwrap_or(false);

            // MATH EDGE: Check if this address was created by us in this transaction
            // If so, we could theoretically know its bytecode.
            // For now, we just ensure the symbolic bytes are consistent with that address.
            let is_known = machine.created_contracts.iter().any(|c| c == &addr);

            for i in 0..l_u {
                let idx = dest_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));
                let byte = if is_destroyed {
                    BV::from_u64(machine.context, 0, 8)
                } else {
                    let prefix = if is_known { "known_code" } else { "extcode" };
                    let name = format!("{}_{}_{}", prefix, addr, i);
                    BV::new_const(machine.context, name.as_str(), 8)
                };
                machine.write_byte(idx, byte);
            }
        }
        // BLOCKHASH (0x40): model as symbolic data for time-dependent paths.
        0x40 => {
            let block_num = machine.sym_stack.pop();
            let num_str = crate::symbolic::z3_ext::u256_from_bv(&block_num)
                .map(|v| format!("{}", v))
                .unwrap_or_else(|| format!("sym_{}", machine.tx_id));
            let name = format!("blockhash_{}", num_str);
            let hash = BV::new_const(machine.context, name.as_str(), 256);
            machine.sym_stack.push(hash);
        }
        _ => {}
    }
}
