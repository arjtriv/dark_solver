use std::fs;

#[test]
fn test_contested_inclusion_benchmark_harness_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for contested benchmark harness audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs").expect(
        "src/storage/contracts_db.rs must be readable for contested benchmark harness audit",
    );

    assert!(
        main_source.contains("contested_benchmark_rows")
            && main_source.contains("CONTESTED_BENCHMARK_SAMPLE_LIMIT")
            && main_source.contains("CONTESTED_BENCHMARK_POLL_MS"),
        "main runtime must load rolling contested benchmark rows with configurable window and cadence"
    );
    assert!(
        main_source.contains("latency_bucket_label")
            && main_source.contains("tip_band_label")
            && main_source.contains("apply_contested_row_to_tally"),
        "main runtime must aggregate contested outcomes by builder/latency bucket/tip band"
    );
    assert!(
        main_source.contains("[BENCH][BUILDER]")
            && main_source.contains("[BENCH][LATENCY]")
            && main_source.contains("[BENCH][TIP]"),
        "contested benchmark harness must publish win/loss reason telemetry across all three dimensions"
    );
    assert!(
        storage_source.contains("pub fn contested_benchmark_rows"),
        "storage layer must expose contested benchmark row extraction"
    );
}
