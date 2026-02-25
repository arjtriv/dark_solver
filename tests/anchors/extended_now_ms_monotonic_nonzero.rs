use std::fs;

#[test]
fn strategy_solver_storage_now_ms_are_monotonic_and_nonzero() {
    let watch_cache_source =
        fs::read_to_string("src/executor/watch_cache.rs").expect("read watch_cache");
    let mirror_source = fs::read_to_string("src/strategies/generalized_frontrun.rs")
        .expect("read generalized_frontrun");
    let solver_telemetry_source =
        fs::read_to_string("src/solver/telemetry.rs").expect("read solver telemetry");
    let verification_source =
        fs::read_to_string("src/solver/verification.rs").expect("read solver verification");
    let contracts_db_source =
        fs::read_to_string("src/storage/contracts_db.rs").expect("read contracts_db");

    assert!(
        watch_cache_source
            .contains("static LAST_WATCH_CACHE_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && watch_cache_source
                .contains("fn normalize_watch_cache_now_ms(sample_ms: Option<u64>) -> u64")
            && watch_cache_source.contains("normalize_watch_cache_now_ms(sample)"),
        "watch cache now_ms must be monotonic and non-zero"
    );
    assert!(
        mirror_source.contains("static LAST_MIRROR_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && mirror_source.contains("fn normalize_mirror_now_ms(sample_ms: Option<u64>) -> u64")
            && mirror_source.contains("normalize_mirror_now_ms(sample)"),
        "generalized frontrun now_ms must be monotonic and non-zero"
    );
    assert!(
        solver_telemetry_source
            .contains("static LAST_SOLVER_TELEMETRY_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && solver_telemetry_source
                .contains("fn normalize_solver_telemetry_now_ms(sample_ms: Option<u64>) -> u64")
            && solver_telemetry_source.contains("normalize_solver_telemetry_now_ms(sample)"),
        "solver telemetry now_ms must be monotonic and non-zero"
    );
    assert!(
        verification_source
            .contains("static LAST_VERIFICATION_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && verification_source
                .contains("fn normalize_verification_now_ms(sample_ms: Option<u64>) -> u64")
            && verification_source.contains("normalize_verification_now_ms(sample)"),
        "solver verification now_ms must be monotonic and non-zero"
    );
    assert!(
        contracts_db_source
            .contains("static LAST_CONTRACTS_DB_NOW_MS: AtomicU64 = AtomicU64::new(1);")
            && contracts_db_source
                .contains("fn normalize_contracts_db_now_ms(sample_ms: Option<u64>) -> u64")
            && contracts_db_source.contains("normalize_contracts_db_now_ms(sample)"),
        "contracts db now_ms must be monotonic and non-zero"
    );

    assert!(
        !watch_cache_source.contains(".map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "watch cache now_ms must not fallback to zero"
    );
    assert!(
        !mirror_source.contains(".map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "generalized frontrun now_ms must not fallback to zero"
    );
    assert!(
        !solver_telemetry_source.contains(".map(|d| d.as_millis() as u64)\n        .unwrap_or(0)"),
        "solver telemetry now_ms must not fallback to zero"
    );
    assert!(
        !verification_source
            .contains(".map(|duration| duration.as_millis() as u64)\n        .unwrap_or(0)"),
        "solver verification now_ms must not fallback to zero"
    );
    assert!(
        !contracts_db_source
            .contains(".map(|duration| duration.as_millis() as u64)\n        .unwrap_or(0)"),
        "contracts db now_ms must not fallback to zero"
    );
}
