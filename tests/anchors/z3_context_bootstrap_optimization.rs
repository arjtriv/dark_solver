use std::fs;

#[test]
fn test_z3_context_bootstrap_uses_sticky_worker_and_reset() {
    let objectives_source = fs::read_to_string("src/tactics/objectives/core.rs")
        .expect("src/tactics/objectives/core.rs must be readable for z3-bootstrap anchor");

    assert!(
        objectives_source.contains("thread_local!"),
        "run_with_z3_solver must keep per-thread sticky worker state"
    );
    assert!(
        objectives_source.contains("STICKY_Z3_WORKER"),
        "z3 bootstrap optimization must define sticky worker storage"
    );
    assert!(
        objectives_source.contains("worker.solver.reset();"),
        "sticky solver must reset assertions between objective invocations"
    );
    assert!(
        objectives_source.contains("configure_solver(worker.ctx, &worker.solver);"),
        "solver configuration must still be re-applied on each invocation"
    );
}
