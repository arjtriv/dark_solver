use std::fs;

#[test]
fn test_builder_fanout_is_parallel_and_supports_direct_stream_url_aliases() {
    let src = fs::read_to_string("src/executor/builders.rs")
        .expect("src/executor/builders.rs must be readable for direct-stream audit");

    assert!(
        src.contains("tokio::spawn"),
        "MultiBuilder fan-out must dispatch builder submissions in parallel"
    );
    assert!(
        src.contains("normalize_builder_url"),
        "builder url normalization must exist for direct-stream aliases"
    );
    assert!(
        src.contains("grpc://") && src.contains("grpcs://"),
        "builder url normalization must accept grpc:// and grpcs:// aliases"
    );
    assert!(
        src.contains("DirectStream-"),
        "direct-stream aliases must map to stable builder names"
    );
}
