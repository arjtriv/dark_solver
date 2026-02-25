use std::fs;

#[test]
fn test_solver_runner_join_failures_are_not_silently_dropped() {
    let runner = fs::read_to_string("src/solver/runner.rs").expect("read solver/runner.rs");
    let main_src = fs::read_to_string("src/main.rs").expect("read main.rs");

    assert!(
        runner.contains("-> Result<Vec<(String, ExploitParams)>>")
            && runner.contains("-> Result<usize>")
            && !runner.contains("handle.await.unwrap_or_default()"),
        "solver runners must return Result and avoid defaulting join failures to empty findings"
    );
    assert!(
        runner.contains("parallel objective runner failed")
            && runner.contains("streaming objective runner failed"),
        "runner must surface worker join/panic failures as explicit errors"
    );
    assert!(
        main_src.contains("Ok(Err(err))"),
        "main pipeline must handle runner-level errors distinctly from task join errors"
    );
}
