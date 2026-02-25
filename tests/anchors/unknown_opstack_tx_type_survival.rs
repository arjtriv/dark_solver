use std::fs;

#[test]
fn test_unknown_opstack_tx_type_survival_is_wired() {
    let scanner_source = fs::read_to_string("src/scanner.rs")
        .expect("src/scanner.rs must be readable for unknown opstack type audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for unknown opstack type audit");

    assert!(
        scanner_source.contains("classify_unknown_opstack_tx_type"),
        "scanner must classify unknown opstack tx/receipt decode variants"
    );
    assert!(
        scanner_source.contains("persist_unknown_opstack_decode"),
        "scanner must persist unknown opstack tx/receipt decode classifications"
    );
    assert!(
        scanner_source.contains("record_unknown_opstack_tx_type"),
        "scanner persistence path must write unknown tx/receipt decode rows into contracts db"
    );
    assert!(
        scanner_source.contains("\"block_full\"")
            && scanner_source.contains("\"tx_by_hash\"")
            && scanner_source.contains("\"tx_receipt\"")
            && scanner_source.contains("\"block_receipts\""),
        "scanner must classify and persist unknown decode errors across full and fallback stages"
    );
    assert!(
        scanner_source.contains("process_block_hash_mode"),
        "scanner must keep tolerant hash/receipt fallback active when decode incompatibility is detected"
    );
    assert!(
        main_source.contains("Some(scanner_db.clone())")
            && main_source.contains("Some(backfill_db)"),
        "main runtime must pass db handles into scanner/backfill workers for unknown-type persistence"
    );
}
