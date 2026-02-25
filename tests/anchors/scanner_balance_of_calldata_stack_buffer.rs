use std::fs;

#[test]
fn test_scanner_balance_of_calldata_stack_buffer_is_wired() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    let fn_start = source
        .find("fn balance_of_calldata(owner: Address) -> Bytes")
        .expect("balance_of_calldata definition");
    let fn_tail = &source[fn_start..];
    let fn_end = fn_tail
        .find("\n}\n\nfn multicall3_address()")
        .expect("end of balance_of_calldata");
    let body = &fn_tail[..fn_end];

    assert!(
        body.contains("let mut call_data = [0u8; 36];"),
        "balance_of_calldata should build calldata on stack."
    );
    assert!(
        body.contains("Bytes::copy_from_slice(&call_data)"),
        "balance_of_calldata should avoid Vec growth/extend allocations."
    );
    assert!(
        !body.contains("extend_from_slice"),
        "balance_of_calldata should not append via Vec::extend_from_slice."
    );
}
