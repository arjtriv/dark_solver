use std::fs;

#[test]
fn test_opstack_decoder_hardening_handles_0x7d_0x7e_without_block_drop() {
    let scanner_source = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for opstack decoder hardening audit");

    assert!(
        scanner_source.contains("extract_unknown_tx_type_token"),
        "scanner must normalize unknown tx-type tokens from decode errors"
    );
    assert!(
        scanner_source.contains("matches!(ty.as_str(), \"0x7d\" | \"0x7e\")"),
        "decode incompatibility gate must explicitly include OP-Stack types 0x7d and 0x7e"
    );
    assert!(
        scanner_source.contains("FULL_BLOCK_HYDRATION_ENABLED.store(false, Ordering::Relaxed)")
            && scanner_source.contains("process_block_hash_mode("),
        "scanner must fail over to tolerant hash/receipt mode instead of skipping block ingestion"
    );
}
