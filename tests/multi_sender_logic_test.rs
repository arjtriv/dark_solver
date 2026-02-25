use dark_solver::symbolic::state::SymbolicMachine;
use revm::primitives::Address;
use z3::{Config, Context, Solver};

#[test]
fn test_multi_sender_schedule_alternates_origin_by_tx_id() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let sender_a = Address::new([0xa1; 20]);
    let sender_b = Address::new([0xb2; 20]);
    machine.set_tx_sender_schedule(vec![sender_a, sender_b]);

    machine.tx_id = 0;
    assert_eq!(machine.effective_tx_origin(Address::ZERO), sender_a);
    machine.tx_id = 1;
    assert_eq!(machine.effective_tx_origin(Address::ZERO), sender_b);
    machine.tx_id = 2;
    assert_eq!(machine.effective_tx_origin(Address::ZERO), sender_a);
}

#[test]
fn test_multi_sender_schedule_is_optional() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let machine = SymbolicMachine::new(&ctx, &solver, None);

    let env_origin = Address::new([0x77; 20]);
    assert_eq!(machine.effective_tx_origin(env_origin), env_origin);
}
