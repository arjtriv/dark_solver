use dark_solver::symbolic::state::SymbolicMachine;
use revm::interpreter::Interpreter;
use revm::{EvmContext, InMemoryDB};
use z3::ast::Ast;
use z3::{Config, Context, Solver};

// Helper to create a machine
fn create_machine<'ctx>(ctx: &'ctx Context, solver: &'ctx Solver<'ctx>) -> SymbolicMachine<'ctx> {
    SymbolicMachine::new(ctx, solver, None)
}

use std::mem::MaybeUninit;

// ... (imports)

#[test]
fn test_selfdestruct_flag() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = create_machine(&ctx, &solver);

    machine
        .sym_stack
        .push(z3::ast::BV::from_u64(&ctx, 0xDEADBEEF, 256));

    // Execute SELFDESTRUCT (0xFF)
    let mut uninit_iter = MaybeUninit::<Interpreter>::uninit();
    let iter = unsafe { uninit_iter.assume_init_mut() };

    let mut uninit_ctxt = MaybeUninit::<EvmContext<InMemoryDB>>::uninit();
    let ctxt = unsafe { uninit_ctxt.assume_init_mut() };

    dark_solver::symbolic::opcodes::control::handle_control::<InMemoryDB>(
        &mut machine,
        iter,
        ctxt,
        0xFF,
    );

    assert!(
        !machine.reverted,
        "SELFDESTRUCT should not set reverted flag"
    );
    assert!(
        machine.self_destructed,
        "SELFDESTRUCT should set self_destructed flag"
    );
}

#[test]
fn test_create_tracking() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = create_machine(&ctx, &solver);

    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 32, 256));
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256));
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256));

    let mut uninit_iter = MaybeUninit::<Interpreter>::uninit();
    let iter = unsafe { uninit_iter.assume_init_mut() };

    let mut uninit_ctxt = MaybeUninit::<EvmContext<InMemoryDB>>::uninit();
    let ctxt = unsafe { uninit_ctxt.assume_init_mut() };

    dark_solver::symbolic::opcodes::calls::handle_calls::<InMemoryDB>(
        &mut machine,
        iter,
        ctxt,
        0xF0,
    );

    assert_eq!(
        machine.created_contracts.len(),
        1,
        "Should track created contract"
    );
    // Verify stack has the new address
    let stack_top = machine.sym_stack.pop();
    let tracked = machine.created_contracts[0].clone();

    // Use Z3 to prove they are equal
    solver.push();
    solver.assert(&stack_top._eq(&tracked));
    assert_eq!(solver.check(), z3::SatResult::Sat);
    solver.pop(1);
}

#[test]
fn test_extcodecopy_known() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = create_machine(&ctx, &solver);

    let known_addr = z3::ast::BV::from_u64(&ctx, 0x12345678, 256);
    machine.created_contracts.push(known_addr.clone());

    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 32, 256));
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256));
    machine.sym_stack.push(z3::ast::BV::from_u64(&ctx, 0, 256));
    machine.sym_stack.push(known_addr);

    let mut uninit_iter = MaybeUninit::<Interpreter>::uninit();
    let iter = unsafe { uninit_iter.assume_init_mut() };

    let mut uninit_ctxt = MaybeUninit::<EvmContext<InMemoryDB>>::uninit();
    let ctxt = unsafe { uninit_ctxt.assume_init_mut() };

    dark_solver::symbolic::opcodes::context::handle_context::<InMemoryDB>(
        &mut machine,
        iter,
        ctxt,
        0x3C,
    );

    // 4. Check memory at 0. It should be named "known_code_..."
    let byte_0 = machine.read_byte(z3::ast::BV::from_u64(&ctx, 0, 256));
    let byte_0_str = format!("{:?}", byte_0);
    // Z3 debug string format is typically like `const(known_code_...)` or just the name
    assert!(
        byte_0_str.contains("known_code"),
        "Should use 'known_code' prefix for known contract interaction, got: {}",
        byte_0_str
    );
}
