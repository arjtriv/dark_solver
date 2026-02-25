use crate::symbolic::state::SymbolicMachine;
use revm::interpreter::{InstructionResult, Interpreter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolicErrorKind {
    MissingConcreteCallTarget,
    NonConcreteCodeOffset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolicError {
    pub pc: usize,
    pub opcode: u8,
    pub z3_state: String,
    pub kind: SymbolicErrorKind,
    pub message: String,
}

impl SymbolicError {
    pub fn from_machine<'ctx>(
        machine: &SymbolicMachine<'ctx>,
        pc: usize,
        opcode: u8,
        kind: SymbolicErrorKind,
        message: impl Into<String>,
    ) -> Self {
        let assertions = machine.solver.get_assertions().len();
        let z3_state = format!(
            "assertions={assertions},solver_depth={},tx_id={}",
            machine.solver_depth, machine.tx_id
        );
        Self {
            pc,
            opcode,
            z3_state,
            kind,
            message: message.into(),
        }
    }
}

pub fn lift_option<'ctx, T>(
    machine: &SymbolicMachine<'ctx>,
    pc: usize,
    opcode: u8,
    kind: SymbolicErrorKind,
    value: Option<T>,
    message: impl Into<String>,
) -> Result<T, SymbolicError> {
    value.ok_or_else(|| SymbolicError::from_machine(machine, pc, opcode, kind, message))
}

pub fn apply_opcode_error<'ctx>(
    machine: &mut SymbolicMachine<'ctx>,
    interpreter: &mut Interpreter,
    err: SymbolicError,
) {
    eprintln!(
        "[ERR] SymbolicError pc={} opcode=0x{:02x} kind={:?} z3_state={} msg={}",
        err.pc, err.opcode, err.kind, err.z3_state, err.message
    );
    machine.reverted = true;
    interpreter.instruction_result = InstructionResult::Revert;
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_lift_option_builds_structured_symbolic_error() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let machine = SymbolicMachine::new(&ctx, &solver, None);

        let lifted: Result<u64, SymbolicError> = lift_option(
            &machine,
            17,
            0xf1,
            SymbolicErrorKind::MissingConcreteCallTarget,
            None,
            "call target is symbolic",
        );

        assert!(lifted.is_err());
        let err = match lifted {
            Ok(_) => unreachable!("expected Err"),
            Err(err) => err,
        };
        assert_eq!(err.pc, 17);
        assert_eq!(err.opcode, 0xf1);
        assert_eq!(err.kind, SymbolicErrorKind::MissingConcreteCallTarget);
        assert!(err.z3_state.contains("assertions="));
    }
}
