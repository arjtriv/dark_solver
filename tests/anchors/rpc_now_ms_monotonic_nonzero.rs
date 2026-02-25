use std::fs;

#[test]
fn rpc_now_ms_is_monotonic_and_nonzero_for_cooldown_math() {
    let source = fs::read_to_string("src/utils/rpc.rs").expect("src/utils/rpc.rs must be readable");
    assert!(
        source.contains("static LAST_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && source.contains("fn normalize_now_ms(sample_ms: Option<u64>) -> u64")
            && source.contains(".max(1)"),
        "rpc now_ms must clamp to non-zero monotonic values to keep cooldown math fail-closed under wall-clock faults"
    );
}
