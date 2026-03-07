use std::fs;

#[test]
fn benchmark_rpc_cli_surface_keeps_multi_endpoint_controls() {
    let source = fs::read_to_string("src/bin/benchmark_rpc.rs").expect("read benchmark_rpc.rs");
    assert!(source.contains("--url"), "benchmark_rpc should keep repeated url flags");
    assert!(source.contains("--urls"), "benchmark_rpc should keep csv url input");
    assert!(source.contains("--json"), "benchmark_rpc should keep json output");
    assert!(
        source.contains("no RPC URLs provided"),
        "benchmark_rpc should still reject empty endpoint sets"
    );
}
