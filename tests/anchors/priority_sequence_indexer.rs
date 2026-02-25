use std::fs;

#[test]
fn priority_sequence_indexer_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("scanner source must be readable");
    assert!(
        scanner.contains("start_priority_sequence_indexer"),
        "scanner must expose start_priority_sequence_indexer"
    );
    assert!(
        scanner.contains("eth_getBlockByNumber"),
        "priority indexer must fetch pending blocks via eth_getBlockByNumber"
    );
    assert!(
        scanner.contains("\"pending\""),
        "priority indexer must use pending block tag"
    );
    assert!(
        scanner.contains("extract_abi_addresses"),
        "priority indexer must extract ABI-like embedded addresses from calldata"
    );

    let main_source = fs::read_to_string("src/main.rs").expect("main source must be readable");
    assert!(
        main_source.contains("start_priority_sequence_indexer"),
        "main must spawn priority sequence indexer"
    );
}
