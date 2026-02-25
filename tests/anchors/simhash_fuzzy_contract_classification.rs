use std::fs;

#[test]
fn test_simhash_fuzzy_contract_classification_is_wired() {
    let db = fs::read_to_string("src/storage/contracts_db.rs").expect("read contracts_db.rs");
    let setup = fs::read_to_string("src/solver/setup.rs").expect("read solver/setup.rs");
    let simhash = fs::read_to_string("src/storage/simhash.rs").expect("read storage/simhash.rs");

    assert!(
        db.contains("CREATE TABLE IF NOT EXISTS bytecode_simhashes")
            && db.contains("idx_bytecode_simhash_band0")
            && db.contains("UpsertBytecodeSimhash")
            && db.contains("lookup_similar_bytecode_slice_by_simhash"),
        "ContractsDb must persist a simhash index and expose a similarity lookup API"
    );

    assert!(
        setup.contains("SIMHASH_CLASSIFICATION_ENABLED")
            && setup.contains("lookup_similar_bytecode_slice_by_simhash")
            && setup.contains("upsert_bytecode_simhash"),
        "solver/setup must optionally reuse bytecode slices via simhash-based template matching"
    );

    assert!(
        simhash.contains("pub fn simhash64")
            && simhash.contains("pub fn hamming_distance64")
            && simhash.contains("pub fn simhash_bands16"),
        "simhash utilities must exist and expose 64-bit simhash + hamming + banding"
    );
}
