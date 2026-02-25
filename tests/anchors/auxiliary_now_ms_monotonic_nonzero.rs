use std::fs;

#[test]
fn scanner_telemetry_blackbox_now_ms_are_monotonic_and_nonzero() {
    let scanner_source = fs::read_to_string("src/scanner.rs").expect("read src/scanner.rs");
    let telemetry_source =
        fs::read_to_string("src/utils/telemetry.rs").expect("read src/utils/telemetry.rs");
    let blackbox_source =
        fs::read_to_string("src/utils/blackbox.rs").expect("read src/utils/blackbox.rs");

    assert!(
        scanner_source.contains("static LAST_SCANNER_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && scanner_source
                .contains("fn normalize_scanner_now_ms(sample_ms: Option<u64>) -> u64")
            && scanner_source.contains("normalize_scanner_now_ms(sample)"),
        "scanner now_ms must use monotonic non-zero normalization"
    );
    assert!(
        telemetry_source.contains("static LAST_TELEMETRY_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && telemetry_source
                .contains("fn normalize_telemetry_now_ms(sample_ms: Option<u64>) -> u64")
            && telemetry_source.contains("normalize_telemetry_now_ms(sample)"),
        "telemetry now_ms must use monotonic non-zero normalization"
    );
    assert!(
        blackbox_source.contains("static LAST_BLACKBOX_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && blackbox_source
                .contains("fn normalize_blackbox_now_ms(sample_ms: Option<u64>) -> u64")
            && blackbox_source.contains("normalize_blackbox_now_ms(sample)"),
        "blackbox now_ms must use monotonic non-zero normalization"
    );

    assert!(
        !scanner_source.contains(".unwrap_or_else(|_| Duration::from_secs(0))"),
        "scanner now_ms must not silently fallback to zero"
    );
    assert!(
        !telemetry_source.contains(".map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "telemetry now_ms must not silently fallback to zero"
    );
    assert!(
        !blackbox_source.contains(".map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "blackbox now_ms must not silently fallback to zero"
    );
}
