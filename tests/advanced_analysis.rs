use dark_solver::symbolic::state::SymbolicMachine;
use dark_solver::symbolic::z3_ext::u256_from_bv;
use revm::interpreter::{CallInputs, CallScheme, CallValue, Interpreter};
use revm::primitives::{Address, Bytes, U256};
use revm::InMemoryDB;
use revm::Inspector;
use z3::{Config, Context, Solver};

// Helper to create a machine
fn create_machine<'ctx>(ctx: &'ctx Context, solver: &'ctx Solver<'ctx>) -> SymbolicMachine<'ctx> {
    SymbolicMachine::new(ctx, solver, None)
}

#[test]
fn test_reentrancy_recursion() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = create_machine(&ctx, &solver);

    let target_addr = z3::ast::BV::from_u64(&ctx, 0x1234, 256);
    let target_addr_native =
        revm::primitives::Address::from_word(revm::primitives::U256::from(0x1234).into());

    // 1. Simulate first call
    machine.call_path.push(target_addr_native);
    // machine.call_depth = 1; // Removed

    // 2. Prepare stack for recursive call: gas, address, value(if applicable), args_offset, args_len, ret_offset, ret_len
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 32, 256)); // ret_len
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256)); // ret_offset
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256)); // args_len
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256)); // args_offset
                                                                 // Value for CALL (0xF1) at index 2? No, stack order: gas, addr, value, args_off, args_len, ret_off, ret_len
                                                                 // Top is ret_len.
                                                                 // 7. ret_len
                                                                 // 6. ret_offset
                                                                 // 5. args_len
                                                                 // 4. args_offset
                                                                 // 3. value
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256)); // value
                                                                 // 2. address
    machine.sym_stack.push(target_addr.clone());
    // 1. gas
    machine
        .sym_stack
        .push(z3::ast::BV::from_u64(&ctx, 10000, 256));

    let mut evm = revm::Evm::builder().with_db(InMemoryDB::default()).build();
    let ctxt = &mut evm.context.evm;
    let iter = &mut Interpreter::default();

    // Simulate CALL (0xF1)
    dark_solver::symbolic::opcodes::calls::handle_calls::<InMemoryDB>(
        &mut machine,
        iter,
        ctxt,
        0xF1,
    );

    let mut call_inputs = CallInputs {
        input: Bytes::new(),
        return_memory_offset: 0..0,
        gas_limit: 10_000,
        bytecode_address: target_addr_native,
        target_address: target_addr_native,
        caller: Address::ZERO,
        value: CallValue::Transfer(U256::ZERO),
        scheme: CallScheme::Call,
        is_static: false,
        is_eof: false,
    };

    let call_outcome = machine.call(ctxt, &mut call_inputs);
    assert!(
        call_outcome.is_none(),
        "Unmodeled call should continue into sub-call"
    );
    assert!(
        machine.reentrancy_detected,
        "Recursive call path should trigger reentrancy detection in Inspector::call"
    );
}

#[test]
fn test_dex_model() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = create_machine(&ctx, &solver);

    let target_addr = z3::ast::BV::from_u64(&ctx, 0x1111222233334444, 256);

    // Prepare stack for getAmountsOut call
    // Stack order for STATICCALL (0xFA): gas, addr, args_off, args_len, ret_off, ret_len

    let args_off = z3::ast::BV::from_u64(&ctx, 0, 256);

    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 32, 256)); // ret_len
    machine
        .sym_stack
        .push(z3::ast::BV::from_u64(&ctx, 100, 256)); // ret_off = 100
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 36, 256)); // args_len = 4 + 32 (sel + amountIn)
    machine.sym_stack.push(args_off.clone()); // args_off = 0
    machine.sym_stack.push(target_addr); // address
    machine
        .sym_stack
        .push(z3::ast::BV::from_u64(&ctx, 10000, 256)); // gas

    // Write selector: getAmountsOut (0xd06ca61f)
    // Selector is first 4 bytes at args_off
    // Write selector: getAmountsOut (0xd06ca61f) bytes manually to ensure they are concrete
    // 0xd0, 0x6c, 0xa6, 0x1f at args_off, +1, +2, +3
    machine.write_byte(args_off.clone(), z3::ast::BV::from_u64(&ctx, 0xd0, 8));
    machine.write_byte(
        args_off.bvadd(&z3::ast::BV::from_u64(&ctx, 1, 256)),
        z3::ast::BV::from_u64(&ctx, 0x6c, 8),
    );
    machine.write_byte(
        args_off.bvadd(&z3::ast::BV::from_u64(&ctx, 2, 256)),
        z3::ast::BV::from_u64(&ctx, 0xa6, 8),
    );
    machine.write_byte(
        args_off.bvadd(&z3::ast::BV::from_u64(&ctx, 3, 256)),
        z3::ast::BV::from_u64(&ctx, 0x1f, 8),
    );

    // Write value: amountIn = 1000
    // At args_off + 4
    let arg_val = z3::ast::BV::from_u64(&ctx, 1000, 256);
    let arg_off_val = args_off.bvadd(&z3::ast::BV::from_u64(&ctx, 4, 256));
    machine.write_word(arg_off_val, arg_val);

    let iter = &mut Interpreter::default();

    let mut evm = revm::Evm::builder().with_db(InMemoryDB::default()).build();
    let ctxt = &mut evm.context.evm;

    // Simulate STATICCALL (0xFA)
    dark_solver::symbolic::opcodes::calls::handle_calls::<InMemoryDB>(
        &mut machine,
        iter,
        ctxt,
        0xFA,
    );

    // Verify logic was handled:
    // Success on stack
    let success = machine.sym_stack.pop();
    assert_eq!(success.as_u64().unwrap(), 1);

    // Verify return value at ret_off (100) is symbolic (derived from get_amount_out)
    // It should NOT be zero or empty.
    let ret_val = machine.read_word(z3::ast::BV::from_u64(&ctx, 100, 256));
    // With unconstrained reserves, getAmountsOut should remain symbolic.
    assert!(
        u256_from_bv(&ret_val).is_none(),
        "Result should remain symbolic under unconstrained reserves"
    );
}
