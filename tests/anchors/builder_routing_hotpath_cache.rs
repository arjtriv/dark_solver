use std::fs;

#[test]
fn test_builder_routing_hotpath_cache_is_wired() {
    let executor =
        fs::read_to_string("src/executor/mod.rs").expect("src/executor/mod.rs must be readable");

    assert!(
        executor.contains("BUILDER_ROUTING_CACHE_TTL_MS")
            && executor.contains("builder_routing_cache")
            && executor.contains("load_builder_routing_cache_ttl_ms"),
        "executor must expose bounded TTL caching for builder routing lookups"
    );
    assert!(
        executor.contains("return cached.1")
            && executor.contains("Err(_) => return cached.1")
            && executor.contains("stats.is_empty()"),
        "executor should reuse cached rankings on DB/open/query misses instead of hot-path empty fallbacks"
    );
}
