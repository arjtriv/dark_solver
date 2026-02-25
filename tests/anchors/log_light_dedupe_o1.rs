use std::fs;

#[test]
fn test_log_light_dedupe_is_o1_without_full_retain() {
    let source = fs::read_to_string("src/scanner.rs").expect("read src/scanner.rs");
    assert!(
        source.contains("struct LightLogDedupe")
            && source.contains("VecDeque")
            && source.contains("fn prune(&mut self")
            && !source.contains("state.retain(|_, last|"),
        "log-light dedupe must use an amortized O(1) TTL FIFO instead of full-map retain sweeps"
    );
}
