use std::fs;

#[test]
fn test_flash_loan_registry_supports_dynamic_chain_and_env_specs() {
    let source = fs::read_to_string("src/protocols/flash_loan/mod.rs")
        .expect("src/protocols/flash_loan/mod.rs must be readable for registry anchor");
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for registry anchor");

    assert!(
        source.contains("provider_specs_for_chain")
            && source.contains("default_provider_specs_for_chain")
            && source.contains("FLASH_LOAN_PROVIDER_SPECS_"),
        "flash-loan registry must be chain-aware and accept chain-specific env specs"
    );
    assert!(
        source.contains("parse_provider_registry_entry")
            && source.contains("load_provider_specs_from_registry_env")
            && source.contains("HashSet"),
        "flash-loan registry must parse provider entries and dedupe deterministically"
    );
    assert!(
        executor_source.contains("select_flash_loan_plan")
            && executor_source.contains("requested_token")
            && executor_source.contains("encode_loan"),
        "executor flash-loan plan selection must preserve requested token and skip incompatible providers"
    );
    assert!(
        executor_source.contains("fallback_amount")
            && executor_source.contains(".flash_loan_legs")
            && executor_source.contains("leg.amount"),
        "executor flash-loan plan selection must be leg-aware for amount sizing, not total-only"
    );
    assert!(
        executor_source.contains("collapsed_flash_loan_routes")
            && executor_source.contains("flash_loan_route_count > 1")
            && executor_source.contains("supports a single wrapped route"),
        "executor must fail-closed when proof requires multi-route flash-loan legs"
    );
    assert!(
        executor_source.contains("select_flash_loan_plan_with_capacity")
            && executor_source.contains("probe_flash_loan_provider_capacity")
            && executor_source.contains("FLASH_LOAN_CAPACITY_PROBE_TIMEOUT_MS"),
        "executor flash-loan routing must include bounded capacity probing for provider realizability"
    );
    assert!(
        executor_source.contains("FLASH_LOAN_CAPACITY_CACHE_TTL_MS")
            && executor_source.contains("flash_loan_capacity_cache")
            && executor_source.contains("probe_flash_loan_provider_capacity_cached"),
        "capacity probing must use a bounded cache to avoid repeated hot-path RPC fanout"
    );
    assert!(
        executor_source
            .contains("flash_loan_required(params.as_ref()) && flash_loan_plan.is_none()")
            && executor_source.contains("no realizable provider route"),
        "executor must fail-closed when a flash-loan-required exploit has no realizable route"
    );
    assert!(
        executor_source.contains("discover_flash_loan_specs_from_factories")
            && executor_source.contains("FLASH_LOAN_DISCOVERY_V2_FACTORIES")
            && executor_source.contains("FLASH_LOAN_DISCOVERY_V3_FACTORIES"),
        "executor flash-loan registry must support runtime factory-based provider discovery"
    );
    assert!(
        executor_source.contains("FLASH_LOAN_DISCOVERY_CACHE_TTL_MS")
            && executor_source.contains("flash_loan_discovery_cache")
            && executor_source.contains("flash_loan_discovery_key"),
        "factory discovery must use a bounded cache key to avoid repeated hot-path probing"
    );
}
