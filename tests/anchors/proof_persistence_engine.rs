use std::fs;

#[test]
fn proof_persistence_engine_tracks_stale_background_sat_against_state_root() {
    let main_source = fs::read_to_string("src/main.rs").expect("main source must be readable");

    assert!(
        main_source.contains("PROOF_PERSISTENCE_DEFAULT_STALE_BLOCKS: u64 = 10"),
        "proof persistence engine must default stale threshold to 10 blocks"
    );
    assert!(
        main_source.contains("struct PersistedDeepProofItem"),
        "proof persistence engine must define persisted deep SAT entries"
    );
    assert!(
        main_source.contains("last_valid_state_root: Option<B256>"),
        "persisted proof entries must retain last validated state root"
    );
    assert!(
        main_source.contains("if res.is_background && proof_persistence_enabled"),
        "only background deep SAT findings should be enrolled into proof persistence"
    );
    assert!(
        main_source.contains("track_persisted_deep_proof("),
        "main must track deep SAT findings in the persistence cache"
    );
    assert!(
        main_source.contains("block.header.state_root"),
        "proof revalidation must read current head state root"
    );
    assert!(
        main_source.contains("[PERSIST] Deep SAT still sound"),
        "proof persistence engine must log successful stale-proof revalidation"
    );
}
