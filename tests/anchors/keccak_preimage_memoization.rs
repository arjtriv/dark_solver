use std::fs;

#[test]
fn test_keccak_preimage_memoization_is_wired() {
    let oracle_source = fs::read_to_string("src/symbolic/oracle.rs")
        .expect("src/symbolic/oracle.rs must be readable for keccak-memoization audit");
    let state_source = fs::read_to_string("src/symbolic/state.rs")
        .expect("src/symbolic/state.rs must be readable for keccak-memoization audit");

    assert!(
        oracle_source.contains("GLOBAL_CONCRETE_KECCAK_PREIMAGE_CACHE"),
        "oracle must expose a process-wide concrete keccak preimage cache"
    );
    assert!(
        oracle_source.contains("hydrate_from_global_cache")
            && oracle_source.contains("GLOBAL_CONCRETE_KECCAK_PREIMAGE_CACHE.read()"),
        "oracle must hydrate worker-local preimage maps from global cache"
    );
    assert!(
        oracle_source.contains("GLOBAL_CONCRETE_KECCAK_PREIMAGE_CACHE.write()"),
        "oracle preimage recording must publish concrete entries into global cache"
    );
    assert!(
        state_source.contains("machine.oracle.hydrate_from_global_cache(context);"),
        "new symbolic machines must import global keccak preimage cache on bootstrap"
    );
    assert!(
        state_source.contains("self.oracle.record_preimage(hash, bv_chunks);")
            && state_source.contains("record_preimage(trace_hash_u256, trace.preimage.clone())"),
        "state keccak recording must route through oracle preimage memoization hooks"
    );
}
