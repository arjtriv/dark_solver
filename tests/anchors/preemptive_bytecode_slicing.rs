use std::fs;

#[test]
fn test_preemptive_bytecode_slicing_is_cached_in_hydration_layer() {
    let setup_source = fs::read_to_string("src/solver/setup.rs")
        .expect("src/solver/setup.rs must be readable for bytecode slicing anchor");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for bytecode slicing anchor");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for bytecode slicing anchor");

    assert!(
        storage_source.contains("CREATE TABLE IF NOT EXISTS bytecode_slices"),
        "contracts db schema must persist bytecode slices by hash"
    );
    assert!(
        storage_source.contains("pub fn lookup_bytecode_slice"),
        "contracts db must expose bytecode slice lookup API"
    );
    assert!(
        storage_source.contains("pub fn upsert_bytecode_slice"),
        "contracts db must expose bytecode slice upsert API"
    );
    assert!(
        setup_source.contains("fn hydrate_bytecode_slice"),
        "setup must hydrate selectors through a bytecode slicing cache stage"
    );
    assert!(
        setup_source.contains("db.lookup_bytecode_slice"),
        "setup hydration must read precomputed selectors from contracts db cache"
    );
    assert!(
        setup_source.contains("db.upsert_bytecode_slice"),
        "setup hydration must persist selector slices on cache miss"
    );
    assert!(
        setup_source.contains("selectors: bytecode_slice.selectors"),
        "target context must consume pre-sliced selectors from hydration cache"
    );
    assert!(
        main_source.contains("Some(&hydrate_db)"),
        "main solve pass must pass contracts db into target-context hydration"
    );
}
