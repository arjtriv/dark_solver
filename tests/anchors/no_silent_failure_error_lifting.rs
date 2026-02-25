use dark_solver::symbolic::error::{lift_option, SymbolicErrorKind};
use dark_solver::symbolic::state::SymbolicMachine;
use z3::{Config, Context, Solver};

#[test]
fn test_error_lifting_anchor_captures_pc_opcode_and_z3_state() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let machine = SymbolicMachine::new(&ctx, &solver, None);

    let lifted: Result<u64, _> = lift_option(
        &machine,
        123,
        0xf1,
        SymbolicErrorKind::MissingConcreteCallTarget,
        None,
        "symbolic CALL target",
    );

    assert!(lifted.is_err());
    let err = match lifted {
        Ok(_) => unreachable!("expected lifted error"),
        Err(err) => err,
    };

    assert_eq!(err.pc, 123);
    assert_eq!(err.opcode, 0xf1);
    assert_eq!(err.kind, SymbolicErrorKind::MissingConcreteCallTarget);
    assert!(err.z3_state.contains("assertions="));
    assert!(err.z3_state.contains("solver_depth="));
}
