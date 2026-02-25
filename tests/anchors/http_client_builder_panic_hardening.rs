use std::fs;

#[test]
fn test_http_client_builder_failures_do_not_panic_in_runtime_paths() {
    let forkdb = fs::read_to_string("src/fork_db.rs").expect("read src/fork_db.rs");
    let builders =
        fs::read_to_string("src/executor/builders.rs").expect("read src/executor/builders.rs");
    let gas_solver =
        fs::read_to_string("src/executor/gas_solver.rs").expect("read src/executor/gas_solver.rs");

    assert!(
        !forkdb.contains("expect(\"forkdb HTTP client must be constructed with timeout\")"),
        "ForkDB shared HTTP client construction must not panic on builder failure"
    );
    assert!(
        !builders.contains("expect(\"builder HTTP client must be constructed with timeout\")"),
        "builder HTTP client construction must not panic on builder failure"
    );
    assert!(
        !gas_solver.contains("expect(\"gas solver HTTP client must be constructed with timeout\")"),
        "gas solver HTTP client construction must not panic on builder failure"
    );
    assert!(
        forkdb.contains("Falling back to default client.")
            && builders.contains("Falling back to default client.")
            && gas_solver.contains("Falling back to default client."),
        "runtime HTTP client constructors must fail open to reqwest::Client::new() with warning"
    );
}
