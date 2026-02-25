use crate::symbolic::state::{Create2Deployment, SymbolicMachine, TokenTransferEvent};
use crate::symbolic::{
    error::{apply_opcode_error, lift_option, SymbolicErrorKind},
    z3_ext::u256_from_bv,
};
use revm::interpreter::Interpreter;
use revm::primitives::{keccak256, Address, U256};
use revm::{Database, EvmContext};
use z3::ast::{Ast, Bool, BV};

/// Copies memory[offset..offset+size] into a fresh symbolic byte array.
/// Shared by RETURN (0xF3) and REVERT (0xFD) — identical logic, different array names.
const SAFE_MEMORY_LIMIT: usize = 4096; // 4KB Limit (Compromise for Solver Stability)

// OP-Stack predeploys (Base/Optimism): key sources of L2 gas-pricing semantics.
const OPSTACK_GAS_PRICE_ORACLE_BYTES: [u8; 20] = [
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0f,
];
const OPSTACK_L1_BLOCK_BYTES: [u8; 20] = [
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x15,
];

fn opstack_gas_price_oracle() -> Address {
    Address::from(OPSTACK_GAS_PRICE_ORACLE_BYTES)
}

fn opstack_l1_block() -> Address {
    Address::from(OPSTACK_L1_BLOCK_BYTES)
}

fn selector_u32(signature: &str) -> u32 {
    let hash = keccak256(signature.as_bytes());
    u32::from_be_bytes([hash.0[0], hash.0[1], hash.0[2], hash.0[3]])
}

fn load_u64_env(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
}

fn opstack_l1_fee_overhead_wei() -> u64 {
    // Default ~0.001 ETH: conservative non-zero so "fee must be paid" checks don't collapse to 0.
    load_u64_env("OPSTACK_L1_FEE_OVERHEAD_WEI").unwrap_or(1_000_000_000_000_000)
}

fn opstack_l1_fee_per_byte_wei() -> u64 {
    // Default 1 gwei per byte: simple linear envelope, bounded by calldata limits.
    load_u64_env("OPSTACK_L1_FEE_PER_BYTE_WEI").unwrap_or(1_000_000_000)
}

fn is_uniswap_v2_oracle_selector(selector: u32) -> bool {
    selector == 0x0902f1ac // getReserves()
}

fn is_chainlink_oracle_selector(selector: u32) -> bool {
    matches!(
        selector,
        0x50d25bcd | // latestAnswer()
        0xfeaf968c // latestRoundData()
    )
}

fn pack_return_data<'ctx>(
    machine: &mut SymbolicMachine<'ctx>,
    offset: &BV<'ctx>,
    size: &BV<'ctx>,
    name: &str,
) -> (z3::ast::Array<'ctx>, BV<'ctx>) {
    let mut ret_array = machine.fresh_byte_array(name);

    // Use a larger bound than the old 1024-byte limit to support larger ABI payloads.
    let safe_limit = crate::symbolic::utils::math::bounded_len(size, SAFE_MEMORY_LIMIT);

    for i in 0..safe_limit {
        let idx = offset.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
            machine.context,
            U256::from(i),
        ));

        // OPTIMIZATION: Check if we are reading from uninitialized memory (zero) to save solver overhead?
        // No, read_byte handles the abstraction.
        let b = machine.read_byte(idx);

        let dest_idx = crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from(i));

        // Guarding the store would be required if the array were reused across contexts.
        // Actually, for a FRESH array, we only care about bytes 0..size.
        // Bytes > size are irrelevant. So we don't strictly need ITE here IF the array is fresh.
        // For the current fresh-array usage, direct store is acceptable.
        // Let's keep it simple: just store.
        ret_array = ret_array.store(&dest_idx, &b);
    }
    (ret_array, size.clone())
}

fn enforce_clean_address_word<'ctx>(machine: &mut SymbolicMachine<'ctx>, addr_word: &BV<'ctx>) {
    let cleaned = crate::symbolic::utils::math::clean_address_word(addr_word);
    machine.solver.assert(&addr_word._eq(&cleaned));
}

fn try_handle_symbolic_precompile<'ctx>(
    machine: &mut SymbolicMachine<'ctx>,
    target_u256: U256,
    args_off: &BV<'ctx>,
    args_len: &BV<'ctx>,
    ret_off: &BV<'ctx>,
    call_site_pc: usize,
) -> bool {
    match target_u256 {
        v if v == U256::from(1u64) => {
            // ECRECOVER (0x01):
            // Simplified symbolic relation: output address is constrained to message-hash low 160 bits.
            let msg_hash = machine.read_word(args_off.clone());
            let recovered = msg_hash.extract(159, 0).zero_ext(96);
            machine.write_word(ret_off.clone(), recovered);
            machine
                .sym_stack
                .push(crate::symbolic::utils::math::one(machine.context));
            true
        }
        v if v == U256::from(5u64) => {
            // MODEXP (0x05):
            // EIP-198 input layout:
            // [baseLen (32)] [expLen (32)] [modLen (32)] [base bytes] [exp bytes] [mod bytes]
            //
            // Soundness gate: bound lengths so the solver does not assume "free" modexp on huge
            // inputs (which would be OOG or outside our 1800ms envelope).
            const MODEXP_HEADER_BYTES: u64 = 96;
            const MODEXP_MAX_COMPONENT_LEN_BYTES: u64 = 32;
            const MODEXP_MAX_TOTAL_INPUT_BYTES: u64 =
                MODEXP_HEADER_BYTES + 3 * MODEXP_MAX_COMPONENT_LEN_BYTES;

            let ctx = machine.context;
            let zero = crate::symbolic::utils::math::zero(ctx);
            let one = crate::symbolic::utils::math::one(ctx);

            let off_32 = crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(32u64));
            let off_64 = crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(64u64));
            let off_header =
                crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(MODEXP_HEADER_BYTES));

            let max_component = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(MODEXP_MAX_COMPONENT_LEN_BYTES),
            );
            let max_total = crate::symbolic::z3_ext::bv_from_u256(
                ctx,
                U256::from(MODEXP_MAX_TOTAL_INPUT_BYTES),
            );

            let base_len = machine.read_word(args_off.clone());
            let exp_len = machine.read_word(args_off.bvadd(&off_32));
            let mod_len = machine.read_word(args_off.bvadd(&off_64));

            // Gas/memory safety envelope: clamp to <=32 bytes per component and <=192 bytes total input.
            machine.solver.assert(&base_len.bvule(&max_component));
            machine.solver.assert(&exp_len.bvule(&max_component));
            machine.solver.assert(&mod_len.bvule(&max_component));
            machine.solver.assert(&args_len.bvule(&max_total));

            // This model is a 256-bit abstraction; require 0 or 32-byte limbs to avoid partial-word ambiguity.
            for len in [&base_len, &exp_len, &mod_len] {
                let is_zero = len._eq(&zero);
                let is_full = len._eq(&max_component);
                machine.solver.assert(&Bool::or(ctx, &[&is_zero, &is_full]));
            }

            let total_needed = base_len.bvadd(&exp_len).bvadd(&mod_len).bvadd(&off_header);
            machine.solver.assert(&args_len.bvuge(&total_needed));

            let offset_base = args_off.bvadd(&off_header);
            let offset_exp = offset_base.bvadd(&base_len);
            let offset_mod = offset_exp.bvadd(&exp_len);

            let base = machine.read_word(offset_base);
            let exponent = machine.read_word(offset_exp);
            let modulus = machine.read_word(offset_mod);

            // If length==0, the corresponding value must be 0.
            machine
                .solver
                .assert(&base_len._eq(&zero).implies(&base._eq(&zero)));
            machine
                .solver
                .assert(&exp_len._eq(&zero).implies(&exponent._eq(&zero)));
            machine
                .solver
                .assert(&mod_len._eq(&zero).implies(&modulus._eq(&zero)));

            let result_name = format!("modexp_result_{}_{}", machine.tx_id, call_site_pc);
            let raw_result = BV::new_const(ctx, result_name.as_str(), 256);

            // If modulus != 0, result must be in [0, modulus).
            let mod_non_zero = modulus._eq(&zero).not();
            machine
                .solver
                .assert(&Bool::implies(&mod_non_zero, &raw_result.bvult(&modulus)));

            let normalized = modulus._eq(&zero).ite(&zero, &raw_result);
            let one_mod = modulus._eq(&zero).ite(&zero, &one.bvurem(&modulus));
            let final_result = exponent._eq(&zero).ite(&one_mod, &normalized);

            machine.write_word(ret_off.clone(), final_result);
            machine.sym_stack.push(one);
            true
        }
        v if v == U256::from(6u64) => {
            // EIP-196 alt_bn128_add (0x06).
            //
            // Concrete semantics: outputs (x,y) (64 bytes). Malformed inputs yield (0,0).
            // Symbolic model: BN254 add is modeled as deterministic UFs with identity for infinity.
            const EXPECTED_LEN: u64 = 128;

            let ctx = machine.context;
            let zero = crate::symbolic::utils::math::zero(ctx);
            let one = crate::symbolic::utils::math::one(ctx);

            let expected_len_bv =
                crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(EXPECTED_LEN));
            let len_ok = args_len.bvuge(&expected_len_bv);

            let mut read_word_or_zero = |word_index: u64| -> BV<'ctx> {
                let required_len = crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(word_index.saturating_add(1).saturating_mul(32)),
                );
                let in_bounds = args_len.bvuge(&required_len);
                let word_off = args_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(word_index.saturating_mul(32)),
                ));
                let raw = machine.read_word(word_off);
                in_bounds.ite(&raw, &zero)
            };

            let x1 = read_word_or_zero(0);
            let y1 = read_word_or_zero(1);
            let x2 = read_word_or_zero(2);
            let y2 = read_word_or_zero(3);

            let inf1 = Bool::and(ctx, &[&x1._eq(&zero), &y1._eq(&zero)]);
            let inf2 = Bool::and(ctx, &[&x2._eq(&zero), &y2._eq(&zero)]);

            let dom = z3::Sort::bitvector(ctx, 256);
            let add_x_decl = z3::FuncDecl::new(ctx, "bn254_add_x", &[&dom, &dom, &dom, &dom], &dom);
            let add_y_decl = z3::FuncDecl::new(ctx, "bn254_add_y", &[&dom, &dom, &dom, &dom], &dom);
            let add_x = add_x_decl
                .apply(&[&x1, &y1, &x2, &y2])
                .as_bv()
                .unwrap_or_else(|| zero.clone());
            let add_y = add_y_decl
                .apply(&[&x1, &y1, &x2, &y2])
                .as_bv()
                .unwrap_or_else(|| zero.clone());

            let out_x_core = inf1.ite(&x2, &inf2.ite(&x1, &add_x));
            let out_y_core = inf1.ite(&y2, &inf2.ite(&y1, &add_y));
            let out_x = len_ok.ite(&out_x_core, &zero);
            let out_y = len_ok.ite(&out_y_core, &zero);

            machine.write_word(ret_off.clone(), out_x);
            machine.write_word(
                ret_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(32u64),
                )),
                out_y,
            );
            machine.sym_stack.push(one);
            true
        }
        v if v == U256::from(7u64) => {
            // EIP-196 alt_bn128_mul (0x07).
            //
            // Concrete semantics: outputs (x,y) (64 bytes). Malformed inputs yield (0,0).
            // Symbolic model: BN254 mul is modeled as deterministic UFs with basic scalar identities.
            const EXPECTED_LEN: u64 = 96;

            let ctx = machine.context;
            let zero = crate::symbolic::utils::math::zero(ctx);
            let one = crate::symbolic::utils::math::one(ctx);

            let expected_len_bv =
                crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(EXPECTED_LEN));
            let len_ok = args_len.bvuge(&expected_len_bv);

            let mut read_word_or_zero = |word_index: u64| -> BV<'ctx> {
                let required_len = crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(word_index.saturating_add(1).saturating_mul(32)),
                );
                let in_bounds = args_len.bvuge(&required_len);
                let word_off = args_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(word_index.saturating_mul(32)),
                ));
                let raw = machine.read_word(word_off);
                in_bounds.ite(&raw, &zero)
            };

            let x = read_word_or_zero(0);
            let y = read_word_or_zero(1);
            let s = read_word_or_zero(2);

            let inf = Bool::and(ctx, &[&x._eq(&zero), &y._eq(&zero)]);
            let s0 = s._eq(&zero);
            let s1 = s._eq(&one);
            let s2 = s._eq(&BV::from_u64(ctx, 2, 256));

            let dom = z3::Sort::bitvector(ctx, 256);
            let mul_x_decl = z3::FuncDecl::new(ctx, "bn254_mul_x", &[&dom, &dom, &dom], &dom);
            let mul_y_decl = z3::FuncDecl::new(ctx, "bn254_mul_y", &[&dom, &dom, &dom], &dom);
            let add_x_decl = z3::FuncDecl::new(ctx, "bn254_add_x", &[&dom, &dom, &dom, &dom], &dom);
            let add_y_decl = z3::FuncDecl::new(ctx, "bn254_add_y", &[&dom, &dom, &dom, &dom], &dom);

            let mul_x = mul_x_decl
                .apply(&[&x, &y, &s])
                .as_bv()
                .unwrap_or_else(|| zero.clone());
            let mul_y = mul_y_decl
                .apply(&[&x, &y, &s])
                .as_bv()
                .unwrap_or_else(|| zero.clone());
            let dbl_x = add_x_decl
                .apply(&[&x, &y, &x, &y])
                .as_bv()
                .unwrap_or_else(|| zero.clone());
            let dbl_y = add_y_decl
                .apply(&[&x, &y, &x, &y])
                .as_bv()
                .unwrap_or_else(|| zero.clone());

            let infinity_case = Bool::or(ctx, &[&inf, &s0]);
            let out_x_core = infinity_case.ite(&zero, &s1.ite(&x, &s2.ite(&dbl_x, &mul_x)));
            let out_y_core = infinity_case.ite(&zero, &s1.ite(&y, &s2.ite(&dbl_y, &mul_y)));
            let out_x = len_ok.ite(&out_x_core, &zero);
            let out_y = len_ok.ite(&out_y_core, &zero);

            machine.write_word(ret_off.clone(), out_x);
            machine.write_word(
                ret_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(32u64),
                )),
                out_y,
            );
            machine.sym_stack.push(one);
            true
        }
        v if v == U256::from(8u64) => {
            // EIP-197 alt_bn128_pairing (0x08):
            //
            // Concrete semantics: returns 32 bytes (0 or 1). The call itself succeeds unless OOG.
            // Invalid input length (not multiple of 192 bytes) yields 0.
            //
            // Symbolic model (quantifier-free, bounded):
            // - deterministically hashes a bounded prefix of input words into a 256-bit digest
            // - pairing_ok(digest) is an uninterpreted predicate
            // - enforces identity: empty input and all-zero (infinity) pairs must validate (=> 1)
            const BYTES_PER_PAIR: u64 = 192;
            const WORDS_PER_PAIR: u64 = 6; // 192B / 32B
            const SAFE_MAX_PAIRS: u64 = 6; // typical verifier uses <=4; keep bounded for solver stability

            let ctx = machine.context;
            let zero = crate::symbolic::utils::math::zero(ctx);
            let one = crate::symbolic::utils::math::one(ctx);

            let len_zero = args_len._eq(&zero);
            let bytes_per_pair_bv =
                crate::symbolic::z3_ext::bv_from_u256(ctx, U256::from(BYTES_PER_PAIR));
            let len_multiple = args_len.bvurem(&bytes_per_pair_bv)._eq(&zero);

            let total_words = WORDS_PER_PAIR.saturating_mul(SAFE_MAX_PAIRS);
            let mut digest = zero.clone();
            let mut all_zero = Bool::from_bool(ctx, true);

            for word_idx in 0..total_words {
                let word_off = args_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from(word_idx.saturating_mul(32)),
                ));

                let word = machine.read_word(word_off);

                // If the input is shorter than this word, treat it as zero (ignored bytes).
                let required_len = crate::symbolic::z3_ext::bv_from_u256(
                    ctx,
                    U256::from((word_idx.saturating_add(1)).saturating_mul(32)),
                );
                let in_bounds = args_len.bvuge(&required_len);
                let included = in_bounds.ite(&word, &zero);

                // Fold into a deterministic digest using existing Keccak UF (2-arg slicing).
                digest = machine
                    .keccak
                    .apply_symbolic(Some(vec![digest.clone(), included.clone()]));

                all_zero = Bool::and(ctx, &[&all_zero, &included._eq(&zero)]);
            }

            let digest_sort = z3::Sort::bitvector(ctx, 256);
            let ok_decl = z3::FuncDecl::new(
                ctx,
                "bn254_pairing_ok",
                &[&digest_sort],
                &z3::Sort::bool(ctx),
            );
            let ok_bool = match ok_decl.apply(&[&digest]).as_bool() {
                Some(v) => v,
                None => {
                    machine.write_word(ret_off.clone(), zero);
                    machine.sym_stack.push(one);
                    return true;
                }
            };

            // Identity axiom: all-zero (infinity) pairs must validate when length is valid/non-empty.
            let non_empty = len_zero.not();
            let identity_case = Bool::and(ctx, &[&len_multiple, &non_empty, &all_zero]);
            machine
                .solver
                .assert(&Bool::implies(&identity_case, &ok_bool));

            let ok_word = ok_bool.ite(&one, &zero);
            let valid_non_empty = Bool::and(ctx, &[&len_multiple, &non_empty]);
            let result_word = len_zero.ite(&one, &valid_non_empty.ite(&ok_word, &zero));

            machine.write_word(ret_off.clone(), result_word);
            machine.sym_stack.push(one);
            true
        }
        _ => false,
    }
}

fn apply_modeled_erc20_transfer<'ctx>(
    machine: &mut SymbolicMachine<'ctx>,
    token: Address,
    from_addr: Address,
    to_addr: Address,
    amount_bv: BV<'ctx>,
    via_transfer_from: bool,
    ret_off: &BV<'ctx>,
) {
    let from_key = (token, from_addr);
    let to_key = (token, to_addr);

    let has_balance;
    {
        let from_bal = machine
            .token_balances
            .entry(from_key)
            .or_insert_with(|| crate::symbolic::utils::math::zero(machine.context));
        has_balance = from_bal.bvuge(&amount_bv);
        let new_from = has_balance.ite(&from_bal.bvsub(&amount_bv), from_bal);
        *from_bal = new_from;
    }

    let modeled_received = if machine.fee_on_transfer_mode {
        let recv_name = format!(
            "fot_recv_{}_{}",
            machine.tx_id,
            machine.token_transfer_events.len()
        );
        let received = BV::new_const(machine.context, recv_name.as_str(), 256);
        machine.solver.assert(&received.bvule(&amount_bv));
        received
    } else {
        amount_bv.clone()
    };

    let actual_received = has_balance.ite(
        &modeled_received,
        &crate::symbolic::utils::math::zero(machine.context),
    );
    {
        let to_bal = machine
            .token_balances
            .entry(to_key)
            .or_insert_with(|| crate::symbolic::utils::math::zero(machine.context));
        let new_to = to_bal.bvadd(&actual_received);
        *to_bal = new_to;
    }

    let success = has_balance.ite(
        &crate::symbolic::utils::math::one(machine.context),
        &crate::symbolic::utils::math::zero(machine.context),
    );
    machine.write_word(ret_off.clone(), success.clone());
    machine.sym_stack.push(success);

    let actual_requested = has_balance.ite(
        &amount_bv,
        &crate::symbolic::utils::math::zero(machine.context),
    );
    machine.token_transfer_events.push(TokenTransferEvent {
        token,
        from: from_addr,
        to: to_addr,
        requested_amount: actual_requested,
        received_amount: actual_received,
        via_transfer_from,
    });
}

pub fn handle_calls<'ctx, DB: Database>(
    machine: &mut SymbolicMachine<'ctx>,
    _interpreter: &mut Interpreter,
    _context: &mut EvmContext<DB>,
    opcode: u8,
) {
    match opcode {
        // CALLDATALOAD (0x35)
        0x35 => {
            let offset_bv = machine.sym_stack.pop();

            let mut word = crate::symbolic::utils::math::zero(machine.context);
            let base_offset = machine.calldata.1.bvadd(&offset_bv);

            for i in 0..32 {
                let idx = base_offset.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));
                let byte = machine
                    .calldata
                    .0
                    .select(&idx)
                    .as_bv()
                    .unwrap_or_else(|| BV::from_u64(machine.context, 0, 8));

                let shift = BV::from_u64(machine.context, (31 - i) as u64 * 8, 256);
                let byte_extended = byte.zero_ext(248); // 8 -> 256
                let shifted = byte_extended.bvshl(&shift);

                word = word.bvor(&shifted);
            }
            machine.sym_stack.push(word);
        }
        // CALLDATASIZE (0x36)
        0x36 => {
            // MATH EDGE: Return symbolic size to allow the solver to bypass length checks
            let name = format!("calldatasize_{}", machine.tx_id);
            let size = BV::new_const(machine.context, name.as_str(), 256);

            // Bound symbolic calldata size to a realistic maximum.
            let max_size =
                crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from(32768));
            machine.solver.assert(&size.bvult(&max_size));

            machine.sym_stack.push(size);
        }
        // CALLDATACOPY (0x37)
        0x37 => {
            let dest_off = machine.sym_stack.pop();
            let src_off = machine.sym_stack.pop();
            let len = machine.sym_stack.pop();

            let base_src = machine.calldata.1.bvadd(&src_off);

            // Fix: Increased limit to 32KB
            let safe_limit = crate::symbolic::utils::math::bounded_len(&len, SAFE_MEMORY_LIMIT);

            for i in 0..safe_limit {
                let idx = base_src.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));
                let byte = machine
                    .calldata
                    .0
                    .select(&idx)
                    .as_bv()
                    .unwrap_or_else(|| BV::from_u64(machine.context, 0, 8));
                let dest_idx = dest_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));

                // Guard the write so only in-bounds bytes mutate destination memory.
                let i_bv = crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from(i));
                let in_bounds = i_bv.bvult(&len);

                let current_val = machine.read_byte(dest_idx.clone());
                let final_val = in_bounds.ite(&byte, &current_val);

                machine.write_byte(dest_idx, final_val);
            }
        }
        // CALLs (0xF1, 0xF2, 0xF4, 0xFA)
        0xF1 | 0xF2 | 0xF4 | 0xFA => {
            let has_value = opcode == 0xF1 || opcode == 0xF2;
            let is_static = opcode == 0xfa;

            let _gas = machine.sym_stack.pop();
            let target_bv = machine.sym_stack.pop();
            enforce_clean_address_word(machine, &target_bv);
            let call_value = if has_value {
                Some(machine.sym_stack.pop())
            } else {
                None
            };
            let args_off = machine.sym_stack.pop();
            let args_len = machine.sym_stack.pop();
            let ret_off = machine.sym_stack.pop();
            let ret_len = machine.sym_stack.pop();

            if let Some(value_bv) = &call_value {
                let sender = _interpreter.contract.target_address;
                machine.track_msg_value_loop_guard(sender, value_bv);
            }

            let call_site_pc = _interpreter.program_counter();
            machine.next_call_site_pc = Some(call_site_pc);
            machine.next_call_args = Some((args_off.clone(), args_len.clone()));
            machine
                .pending_calls
                .push((ret_off.clone(), ret_len.clone()));

            let pc = _interpreter.program_counter();
            let target_u256 = match lift_option(
                machine,
                pc,
                opcode,
                SymbolicErrorKind::MissingConcreteCallTarget,
                u256_from_bv(&target_bv),
                "CALL target must resolve to concrete address",
            ) {
                Ok(target) => target,
                Err(err) => {
                    // Graceful revert: push failure (0), clear pending call metadata, and halt branch.
                    machine
                        .sym_stack
                        .push(crate::symbolic::utils::math::zero(machine.context));
                    machine.pending_calls.pop();
                    machine.next_call_site_pc = None;
                    apply_opcode_error(machine, _interpreter, err);
                    return;
                }
            };
            let target_addr = Address::from_word(target_u256.into());

            // Store target for Inspector::call to perform reentrancy detection
            // and manage call_path lifetime across the actual sub-call execution.
            machine.next_call_target = Some((target_addr, is_static));

            let is_external_call = opcode == 0xF1 || opcode == 0xFA;
            let mut handled = false;
            if is_external_call
                && try_handle_symbolic_precompile(
                    machine,
                    target_u256,
                    &args_off,
                    &args_len,
                    &ret_off,
                    call_site_pc,
                )
            {
                handled = true;
            }

            // Protocol modeling (ERC20 / AMM / lending).
            // Only intercept CALL (0xF1) and STATICCALL (0xFA).
            // DELEGATECALL (0xF4) and CALLCODE (0xF2) execute in the *caller's* context.
            // Applying external token logic during DELEGATECALL/CALLCODE is incorrect because
            // execution remains in the caller's storage/context and creates false positives.
            match opcode {
                0xF1 | 0xF2 | 0xF4 | 0xFA => {}
                _ => {}
            }

            if is_external_call {
                if let Some(a_len_u) = u256_from_bv(&args_len).and_then(|v| usize::try_from(v).ok())
                {
                    if a_len_u >= 4 {
                        let selector_bv = machine
                            .read_word(args_off.clone())
                            .extract(255, 224)
                            .simplify();
                        if let Some(selector) =
                            u256_from_bv(&selector_bv).and_then(|v| u32::try_from(v).ok())
                        {
                            // ORACLE DEPENDENCY DISCOVERY (Priority 1)
                            if is_static && is_uniswap_v2_oracle_selector(selector) {
                                machine.record_oracle_dependency(
                                    target_addr,
                                    alloy::primitives::U256::from(selector),
                                    crate::symbolic::state::OracleType::UniV2Reserves,
                                );
                            }
                            if is_static && is_chainlink_oracle_selector(selector) {
                                machine.record_oracle_dependency(
                                    target_addr,
                                    alloy::primitives::U256::from(selector),
                                    crate::symbolic::state::OracleType::ChainlinkFeed,
                                );
                            }
                            if is_static
                                && matches!(
                                    crate::protocols::erc4626::classify_selector(selector),
                                    Some(crate::protocols::erc4626::Erc4626Selector::TotalAssets)
                                )
                            {
                                machine.record_oracle_dependency(
                                    target_addr,
                                    alloy::primitives::U256::from(selector),
                                    crate::symbolic::state::OracleType::ERC4626TotalAssets,
                                );
                            }

                            // OP-Stack gas-pricing predeploy modeling (Base/Optimism):
                            // `GasPriceOracle.getL1Fee(bytes)` is used by many contracts to compute total fees.
                            // Treating it as an opaque external call creates "drift" false-positives.
                            if is_static && target_addr == opstack_gas_price_oracle() {
                                let get_l1_fee = selector_u32("getL1Fee(bytes)");
                                if selector == get_l1_fee {
                                    let overhead = BV::from_u64(
                                        machine.context,
                                        opstack_l1_fee_overhead_wei(),
                                        256,
                                    );
                                    let per_byte = BV::from_u64(
                                        machine.context,
                                        opstack_l1_fee_per_byte_wei(),
                                        256,
                                    );
                                    let fee_512 = crate::symbolic::utils::math::extend_to_512(
                                        machine.context,
                                        &args_len,
                                    )
                                    .bvmul(&crate::symbolic::utils::math::extend_to_512(
                                        machine.context,
                                        &per_byte,
                                    ))
                                    .bvadd(
                                        &crate::symbolic::utils::math::extend_to_512(
                                            machine.context,
                                            &overhead,
                                        ),
                                    );
                                    let fee = fee_512.extract(255, 0);
                                    machine.write_word(ret_off.clone(), fee);
                                    machine
                                        .sym_stack
                                        .push(crate::symbolic::utils::math::one(machine.context));
                                    handled = true;
                                }
                            }
                            if is_static && target_addr == opstack_l1_block() {
                                // Placeholder: model the L1Block predeploy as read-only and always-successful
                                // for known getters by returning bounded symbolic values when requested by name.
                                // Currently we only need it as a drift-safe external surface marker.
                            }

                            match selector {
                                s if matches!(
                                    crate::protocols::erc4626::classify_selector(s),
                                    Some(crate::protocols::erc4626::Erc4626Selector::TotalAssets)
                                ) =>
                                {
                                    let current_assets = machine
                                        .erc4626_state(target_addr)
                                        .map(|state| state.current_assets.clone());
                                    if let Some(assets) = current_assets {
                                        machine.write_word(ret_off.clone(), assets);
                                        machine.sym_stack.push(crate::symbolic::utils::math::one(
                                            machine.context,
                                        ));
                                        handled = true;
                                    }
                                }
                                s if matches!(
                                    crate::protocols::erc4626::classify_selector(s),
                                    Some(crate::protocols::erc4626::Erc4626Selector::TotalSupply)
                                ) =>
                                {
                                    let current_supply = machine
                                        .erc4626_state(target_addr)
                                        .map(|state| state.current_supply.clone());
                                    if let Some(supply) = current_supply {
                                        machine.write_word(ret_off.clone(), supply);
                                        machine.sym_stack.push(crate::symbolic::utils::math::one(
                                            machine.context,
                                        ));
                                        handled = true;
                                    }
                                }
                                s if matches!(
                                    crate::protocols::erc4626::classify_selector(s),
                                    Some(crate::protocols::erc4626::Erc4626Selector::Deposit)
                                        | Some(crate::protocols::erc4626::Erc4626Selector::Mint)
                                ) =>
                                {
                                    let amount = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(4),
                                        ),
                                    ));
                                    if is_static {
                                        machine.write_word(
                                            ret_off.clone(),
                                            crate::symbolic::utils::math::zero(machine.context),
                                        );
                                        machine.sym_stack.push(crate::symbolic::utils::math::zero(
                                            machine.context,
                                        ));
                                        handled = true;
                                    } else {
                                        let mut modeled = None;
                                        if let Some(state) = machine.erc4626_state(target_addr) {
                                            let old_assets = state.current_assets.clone();
                                            let old_supply = state.current_supply.clone();
                                            let new_assets = old_assets.bvadd(&amount);
                                            let new_supply = old_supply.bvadd(&amount);
                                            state.current_assets = new_assets.clone();
                                            state.current_supply = new_supply.clone();
                                            state.touched = true;
                                            modeled = Some((
                                                old_assets, old_supply, new_assets, new_supply,
                                            ));
                                        }

                                        if let Some((
                                            old_assets,
                                            old_supply,
                                            new_assets,
                                            new_supply,
                                        )) = modeled
                                        {
                                            machine.solver.assert(&new_assets.bvuge(&old_assets));
                                            machine.solver.assert(&new_supply.bvuge(&old_supply));
                                            // Generic model assumes 1:1 asset/share conversion envelope.
                                            machine.write_word(ret_off.clone(), amount.clone());
                                            machine.sym_stack.push(
                                                crate::symbolic::utils::math::one(machine.context),
                                            );
                                            handled = true;
                                        }
                                    }
                                }
                                s if matches!(
                                    crate::protocols::erc4626::classify_selector(s),
                                    Some(crate::protocols::erc4626::Erc4626Selector::Withdraw)
                                        | Some(crate::protocols::erc4626::Erc4626Selector::Redeem)
                                ) =>
                                {
                                    let amount = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(4),
                                        ),
                                    ));
                                    if is_static {
                                        machine.write_word(
                                            ret_off.clone(),
                                            crate::symbolic::utils::math::zero(machine.context),
                                        );
                                        machine.sym_stack.push(crate::symbolic::utils::math::zero(
                                            machine.context,
                                        ));
                                        handled = true;
                                    } else {
                                        let mut modeled = None;
                                        let ctx = machine.context;
                                        if let Some(state) = machine.erc4626_state(target_addr) {
                                            let has_assets = state.current_assets.bvuge(&amount);
                                            let has_supply = state.current_supply.bvuge(&amount);
                                            let can_burn = z3::ast::Bool::and(
                                                ctx,
                                                &[&has_assets, &has_supply],
                                            );

                                            let reduced_assets =
                                                state.current_assets.bvsub(&amount);
                                            let reduced_supply =
                                                state.current_supply.bvsub(&amount);
                                            state.current_assets = can_burn
                                                .ite(&reduced_assets, &state.current_assets);
                                            state.current_supply = can_burn
                                                .ite(&reduced_supply, &state.current_supply);
                                            state.touched = true;

                                            let out_amount = can_burn.ite(
                                                &amount,
                                                &crate::symbolic::utils::math::zero(
                                                    machine.context,
                                                ),
                                            );
                                            let success = can_burn.ite(
                                                &crate::symbolic::utils::math::one(machine.context),
                                                &crate::symbolic::utils::math::zero(
                                                    machine.context,
                                                ),
                                            );
                                            modeled = Some((out_amount, success));
                                        }

                                        if let Some((out_amount, success)) = modeled {
                                            machine.write_word(ret_off.clone(), out_amount);
                                            machine.sym_stack.push(success);
                                            handled = true;
                                        }
                                    }
                                }
                                s if crate::protocols::uniswap_v4::is_pool_manager_selector(s) => {
                                    let modeled_words =
                                        crate::protocols::uniswap_v4::modeled_pool_manager_return_words(
                                            selector,
                                        );
                                    for word_idx in 0..modeled_words {
                                        let offset =
                                            ret_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                                                machine.context,
                                                U256::from((word_idx * 32) as u64),
                                            ));
                                        let ret_word = if word_idx == 0 {
                                            BV::from_u64(machine.context, selector as u64, 256)
                                        } else {
                                            let ret_name = format!(
                                                "v4_pool_ret_{}_{}_{}",
                                                machine.tx_id, selector, word_idx
                                            );
                                            BV::new_const(machine.context, ret_name.as_str(), 256)
                                        };
                                        machine.write_word(offset, ret_word);
                                    }
                                    machine
                                        .sym_stack
                                        .push(crate::symbolic::utils::math::one(machine.context));
                                    handled = true;
                                }
                                s if crate::protocols::uniswap_v4::is_hook_callback_selector(s) => {
                                    machine.record_uniswap_v4_hook_call(
                                        target_addr,
                                        selector,
                                        call_site_pc,
                                        is_static,
                                    );

                                    let modeled_words =
                                        crate::protocols::uniswap_v4::modeled_hook_return_words(
                                            selector,
                                        );
                                    for word_idx in 0..modeled_words {
                                        let offset =
                                            ret_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                                                machine.context,
                                                U256::from((word_idx * 32) as u64),
                                            ));
                                        let ret_word = if word_idx == 0 {
                                            BV::from_u64(machine.context, selector as u64, 256)
                                        } else {
                                            let ret_name = format!(
                                                "v4_hook_ret_{}_{}_{}",
                                                machine.tx_id, selector, word_idx
                                            );
                                            BV::new_const(machine.context, ret_name.as_str(), 256)
                                        };
                                        machine.write_word(offset, ret_word);
                                    }
                                    machine
                                        .sym_stack
                                        .push(crate::symbolic::utils::math::one(machine.context));
                                    handled = true;
                                }
                                s if is_uniswap_v2_oracle_selector(s) => {
                                    if let Some((r0, r1)) =
                                        machine.manipulated_reserves.get(&target_addr).cloned()
                                    {
                                        // Uniswap V2 getReserves() returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
                                        machine.write_word(ret_off.clone(), r0.clone());
                                        machine.write_word(
                                            ret_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                                                machine.context,
                                                U256::from(32),
                                            )),
                                            r1.clone(),
                                        );
                                        // Timestamp can be 0 or a dummy value
                                        machine.write_word(
                                            ret_off.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                                                machine.context,
                                                U256::from(64),
                                            )),
                                            crate::symbolic::utils::math::zero(machine.context),
                                        );

                                        machine.sym_stack.push(crate::symbolic::utils::math::one(
                                            machine.context,
                                        ));
                                        handled = true;
                                    }
                                }
                                0x70a08231 => {
                                    // balanceOf(address)
                                    let owner_bv = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(4),
                                        ),
                                    ));
                                    enforce_clean_address_word(machine, &owner_bv);
                                    if let Some(owner_u256) = u256_from_bv(&owner_bv) {
                                        let owner_addr = Address::from_word(owner_u256.into());
                                        if let Some(bal) =
                                            machine.token_balances.get(&(target_addr, owner_addr))
                                        {
                                            machine.write_word(ret_off.clone(), bal.clone());
                                            machine.sym_stack.push(
                                                crate::symbolic::utils::math::one(machine.context),
                                            );
                                            handled = true;
                                        }
                                    } else {
                                        tracing::debug!(
                                            "[SYMBOLIC] skipping modeled balanceOf for non-concrete owner"
                                        );
                                    }
                                }
                                0xa9059cbb => {
                                    // transfer(address,uint256)
                                    let to_bv = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(4),
                                        ),
                                    ));
                                    enforce_clean_address_word(machine, &to_bv);
                                    let amount_bv = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(36),
                                        ),
                                    ));
                                    if let Some(to_u256) = u256_from_bv(&to_bv) {
                                        let to_addr = Address::from_word(to_u256.into());
                                        // For sub-calls, `msg.sender` is the calling contract, not the EOA.
                                        let from_addr = _interpreter.contract.target_address;
                                        apply_modeled_erc20_transfer(
                                            machine,
                                            target_addr,
                                            from_addr,
                                            to_addr,
                                            amount_bv,
                                            false,
                                            &ret_off,
                                        );
                                        handled = true;
                                    } else {
                                        tracing::debug!(
                                            "[SYMBOLIC] skipping modeled transfer for non-concrete recipient"
                                        );
                                    }
                                }
                                0x23b872dd => {
                                    // transferFrom(address,address,uint256)
                                    let from_bv = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(4),
                                        ),
                                    ));
                                    enforce_clean_address_word(machine, &from_bv);
                                    let to_bv = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(36),
                                        ),
                                    ));
                                    enforce_clean_address_word(machine, &to_bv);
                                    let amount_bv = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(68),
                                        ),
                                    ));
                                    match (u256_from_bv(&from_bv), u256_from_bv(&to_bv)) {
                                        (Some(from_u256), Some(to_u256)) => {
                                            let from_addr = Address::from_word(from_u256.into());
                                            let to_addr = Address::from_word(to_u256.into());
                                            apply_modeled_erc20_transfer(
                                                machine,
                                                target_addr,
                                                from_addr,
                                                to_addr,
                                                amount_bv,
                                                true,
                                                &ret_off,
                                            );
                                            handled = true;
                                        }
                                        _ => {
                                            tracing::debug!(
                                                "[SYMBOLIC] skipping modeled transferFrom for non-concrete participants"
                                            );
                                        }
                                    }
                                }
                                // Uniswap V2: getAmountsOut(uint, address[])
                                0xd06ca61f => {
                                    let amount_in = machine.read_word(args_off.bvadd(
                                        &crate::symbolic::z3_ext::bv_from_u256(
                                            machine.context,
                                            U256::from(4),
                                        ),
                                    ));
                                    let r_in = BV::new_const(machine.context, "res_in", 256);
                                    let r_out = BV::new_const(machine.context, "res_out", 256);

                                    let amount_out = crate::protocols::uniswap_v2::get_amount_out(
                                        &amount_in, &r_in, &r_out,
                                    );
                                    machine.write_word(ret_off.clone(), amount_out);
                                    machine
                                        .sym_stack
                                        .push(BV::from_u64(machine.context, 1, 256));
                                    handled = true;
                                }
                                // Lending: mint(uint) -> uint
                                0xa0712d68 => {
                                    let err_code =
                                        crate::symbolic::utils::math::zero(machine.context);
                                    machine.write_word(ret_off.clone(), err_code);
                                    machine
                                        .sym_stack
                                        .push(crate::symbolic::utils::math::zero(machine.context));
                                    handled = true;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            if handled {
                // SHORT-CIRCUIT: Tell Inspector::call to skip the actual sub-call.
                // The protocol model already wrote return data to memory and pushed
                // the success value to the symbolic stack.
                machine.call_handled = true;
                // Set last_return_data so RETURNDATASIZE/RETURNDATACOPY work after this call
                let ret_name = format!("handled_ret_{}", machine.tx_id);
                let modeled_size = if is_external_call {
                    match target_u256 {
                        v if v == U256::from(1u64) => Some(U256::from(32u64)),
                        v if v == U256::from(6u64) => Some(U256::from(64u64)),
                        v if v == U256::from(7u64) => Some(U256::from(64u64)),
                        v if v == U256::from(8u64) => Some(U256::from(32u64)),
                        _ => None,
                    }
                } else {
                    None
                };
                let size_bv = modeled_size
                    .map(|v| crate::symbolic::z3_ext::bv_from_u256(machine.context, v))
                    .unwrap_or_else(|| ret_len.clone());
                machine.last_return_data = (machine.fresh_byte_array(&ret_name), size_bv);
            }

            if !handled {
                // Standard Execution (White Box):
                // We let REVM execute the call. The Inspector::call_end hook will handle
                // writing the actual return data to memory.
                // We just need to push a placeholder stack value (which will be discarded/overwritten by call_end).
                machine
                    .sym_stack
                    .push(crate::symbolic::utils::math::zero(machine.context));
            }
        }
        // RETURN (0xF3)
        0xF3 => {
            let offset = machine.sym_stack.pop();
            let size = machine.sym_stack.pop();
            machine.current_return_data = pack_return_data(machine, &offset, &size, "return_data");
        }
        // REVERT (0xFD)
        0xFD => {
            let offset = machine.sym_stack.pop();
            let size = machine.sym_stack.pop();
            machine.current_return_data = pack_return_data(machine, &offset, &size, "revert_data");
            machine.reverted = true;
        }
        // CREATE (0xF0)
        0xF0 => {
            let _value = machine.sym_stack.pop();
            let _offset = machine.sym_stack.pop();
            let _length = machine.sym_stack.pop();
            // MATH EDGE: Return symbolic address - allows solver to reason about deployed contracts
            let addr = BV::new_const(machine.context, "created_addr", 256);
            machine.created_contracts.push(addr.clone());
            machine.sym_stack.push(addr);
        }
        // CREATE2 (0xF5) - Deterministic deployment
        0xF5 => {
            let _value = machine.sym_stack.pop();
            let offset = machine.sym_stack.pop();
            let length = machine.sym_stack.pop();
            let salt = machine.sym_stack.pop();

            let deployer = _interpreter.contract.target_address;
            let declared_len_opt: Option<usize> =
                u256_from_bv(&length).and_then(|v| v.try_into().ok());
            let declared_len = declared_len_opt.unwrap_or(SAFE_MEMORY_LIMIT);
            let analyze_len = declared_len.min(SAFE_MEMORY_LIMIT);

            let mut concrete_init_code = Vec::with_capacity(analyze_len);
            let mut fully_concrete =
                declared_len_opt.is_some() && declared_len <= SAFE_MEMORY_LIMIT;
            for i in 0..analyze_len {
                let idx = offset.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                    machine.context,
                    U256::from(i),
                ));
                let b = machine.read_byte(idx).simplify();
                if let Some(byte_u64) = u256_from_bv(&b).and_then(|v| u8::try_from(v).ok()) {
                    concrete_init_code.push(byte_u64);
                } else {
                    fully_concrete = false;
                    break;
                }
            }

            let init_code_hash = if fully_concrete && concrete_init_code.len() == analyze_len {
                let hash = keccak256(concrete_init_code.as_slice());
                crate::symbolic::z3_ext::bv_from_u256(machine.context, U256::from_be_bytes(hash.0))
            } else {
                let mut hash_inputs = vec![length.clone()];
                for chunk in 0..3usize {
                    let chunk_off = offset.bvadd(&crate::symbolic::z3_ext::bv_from_u256(
                        machine.context,
                        U256::from(chunk * 32),
                    ));
                    hash_inputs.push(machine.read_word(chunk_off));
                }
                machine.keccak.apply_symbolic(Some(hash_inputs))
            };

            let predicted_addr = machine.predict_create2_address(deployer, &salt, &init_code_hash);
            let init_audit = SymbolicMachine::audit_create2_init_code(
                &concrete_init_code,
                declared_len,
                concrete_init_code.len(),
            );

            machine.create2_deployments.push(Create2Deployment {
                deployer,
                salt: salt.clone(),
                init_code_hash: init_code_hash.clone(),
                predicted_address: predicted_addr.clone(),
                audit: init_audit,
            });
            machine.created_contracts.push(predicted_addr.clone());
            machine.sym_stack.push(predicted_addr);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{is_chainlink_oracle_selector, is_uniswap_v2_oracle_selector};

    #[test]
    fn test_uniswap_v2_oracle_selector_detection() {
        assert!(is_uniswap_v2_oracle_selector(0x0902f1ac));
        assert!(!is_uniswap_v2_oracle_selector(0x50d25bcd));
    }

    #[test]
    fn test_chainlink_oracle_selector_detection() {
        assert!(is_chainlink_oracle_selector(0x50d25bcd));
        assert!(is_chainlink_oracle_selector(0xfeaf968c));
        assert!(!is_chainlink_oracle_selector(0x0902f1ac));
    }
}
