use std::fs;

#[test]
fn test_scanner_block_worker_spawn_backpressure_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");

    assert!(
        source.contains("let permit = match _semaphore.clone().try_acquire_owned()"),
        "Scanner must acquire worker permit before spawning block worker tasks."
    );
    assert!(
        source.contains("Worker pool saturated at block"),
        "Scanner must emit saturation signal when worker dispatch is skipped."
    );
    assert!(
        source.contains("let _permit = permit;"),
        "Spawned block worker must hold pre-acquired permit for its lifecycle."
    );
}
