use std::fs;

#[test]
fn test_scanner_pending_candidate_linear_dedupe_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    let fn_start = source
        .find("async fn process_pending_tx_candidate")
        .expect("pending candidate function");
    let body = &source[fn_start..];

    assert!(
        body.contains("let mut candidates: Vec<Address> = Vec::with_capacity"),
        "Pending ingestion should use bounded Vec candidate staging."
    );
    assert!(
        body.contains("if !candidates.contains(&addr)"),
        "Pending ingestion should perform bounded linear dedupe without HashSet allocation."
    );
    assert!(
        !body.contains("let mut candidates: HashSet<Address>"),
        "Pending ingestion should not allocate HashSet per tx."
    );
}
