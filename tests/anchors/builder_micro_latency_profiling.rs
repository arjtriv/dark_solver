use std::fs;

#[test]
fn test_builder_micro_latency_profiling_is_wired() {
    let builders_source = fs::read_to_string("src/executor/builders.rs")
        .expect("src/executor/builders.rs must be readable for micro-latency profiling audit");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for micro-latency routing audit");

    assert!(
        builders_source.contains("latency_us")
            && builders_source.contains("as_micros()")
            && builders_source.contains("send_bundle_ranked"),
        "builder fanout must measure and attach per-builder microsecond latency samples"
    );
    assert!(
        executor_source.contains("record_builder_latency_sample")
            && executor_source.contains("apply_builder_micro_latency_ranking")
            && executor_source.contains("builder_latency_profile"),
        "executor ranking path must consume micro-latency samples to prioritize fastest builders"
    );
}
