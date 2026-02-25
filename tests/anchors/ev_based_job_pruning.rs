use std::fs;

#[test]
fn test_ev_based_job_pruning_is_wired() {
    let main = fs::read_to_string("src/main.rs").expect("src/main.rs must be readable");
    assert!(
        main.contains("MIN_EXPECTED_PROFIT_WEI"),
        "main must support MIN_EXPECTED_PROFIT_WEI floor"
    );
    assert!(
        main.contains("[EV-PRUNE] Dropped SAT finding"),
        "main must emit EV-PRUNE label when dropping under floor"
    );
}
