use std::fs;

#[test]
fn test_executor_signing_keeps_bytes_until_bundle_boundary() {
    let exec_source = fs::read_to_string("src/executor/mod.rs").expect("read executor/mod.rs");
    let multi_source =
        fs::read_to_string("src/executor/multi_block.rs").expect("read executor/multi_block.rs");

    assert!(
        exec_source.contains("group_txs: &mut Vec<AlloyBytes>")
            && exec_source.contains("let mut group_txs: Vec<AlloyBytes> = Vec::new();")
            && exec_source.contains("group_txs.push(AlloyBytes::from(signed.encoded_2718()));"),
        "executor signing path must keep signed txs as bytes instead of per-tx hex strings"
    );
    assert!(
        multi_source.contains("signed_txs_by_group: &BTreeMap<u64, Vec<AlloyBytes>>")
            && multi_source.contains("map(|tx| format!(\"0x{:x}\", tx))"),
        "hex encoding must happen once at bundle construction boundary"
    );
}
