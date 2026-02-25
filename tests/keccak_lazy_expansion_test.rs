use dark_solver::symbolic::patterns::SHA3Trace;
use dark_solver::symbolic::state::SymbolicMachine;
use z3::ast::BV;
use z3::{Config, Context, Solver};

#[test]
fn test_keccak_chain_expands_only_for_relevant_slot() {
    let cfg = Config::new();
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);
    let mut machine = SymbolicMachine::new(&ctx, &solver, None);

    let base = BV::from_u64(&ctx, 0, 256);
    let k1 = BV::new_const(&ctx, "lazy_k1", 256);
    let k2 = BV::new_const(&ctx, "lazy_k2", 256);
    let k3 = BV::new_const(&ctx, "lazy_k3", 256);

    let s1 = machine
        .keccak
        .keccak_256_64
        .apply(&[&k1, &base])
        .as_bv()
        .unwrap();
    machine.record_sha3(SHA3Trace {
        preimage: vec![k1.clone(), base.clone()],
        hash: s1.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 10,
    });

    let s2 = machine
        .keccak
        .keccak_256_64
        .apply(&[&k2, &s1])
        .as_bv()
        .unwrap();
    machine.record_sha3(SHA3Trace {
        preimage: vec![k2.clone(), s1.clone()],
        hash: s2.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 20,
    });

    let s3 = machine
        .keccak
        .keccak_256_64
        .apply(&[&k3, &s2])
        .as_bv()
        .unwrap();
    machine.record_sha3(SHA3Trace {
        preimage: vec![k3.clone(), s2.clone()],
        hash: s3.clone(),
        size: BV::from_u64(&ctx, 64, 256),
        pc: 30,
    });

    assert!(
        machine.pending_keccak_chains.len() >= 2,
        "expected queued links for nested keccak chain"
    );
    assert!(
        machine
            .pending_keccak_chains
            .iter()
            .all(|link| !link.expanded),
        "links should start unexpanded"
    );

    let unrelated = BV::new_const(&ctx, "unrelated_slot", 256);
    machine.materialize_keccak_chain_for_slot(&unrelated);
    assert!(
        machine
            .pending_keccak_chains
            .iter()
            .all(|link| !link.expanded),
        "unrelated slot must not trigger expansion"
    );

    machine.materialize_keccak_chain_for_slot(&s3);
    assert!(
        machine
            .pending_keccak_chains
            .iter()
            .any(|link| link.expanded),
        "relevant slot should trigger lazy expansion"
    );
}
