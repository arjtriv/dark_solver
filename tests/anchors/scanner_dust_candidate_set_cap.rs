use std::fs;

#[test]
fn test_scanner_dust_candidates_are_capped_and_bounded_per_block() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("SCAN_DUST_CANDIDATE_SET_MAX_PER_BLOCK")
            && source.contains("load_dust_candidate_set_max_per_block")
            && source.contains("bounded_insert_dust_candidate"),
        "scanner must enforce a hard per-block cap on dust candidate set growth"
    );
    assert!(
        source
            .contains("let mut candidates: Vec<Address> = dust_candidates.into_iter().collect();")
            && source.contains("candidates.truncate(max_dust_checks);"),
        "full-block dust sweeps must drain a bounded candidate list"
    );
}
