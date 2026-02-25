use std::fs;

#[test]
fn abstract_state_independent_proofs_use_range_constraints_instead_of_hardcoded_slots() {
    let invariants_source =
        fs::read_to_string("src/tactics/objectives/objectives_invariants_vaults.rs")
            .expect("objectives_invariants_vaults source must be readable");
    let lending_source = fs::read_to_string("src/tactics/objectives/objectives_lending_oracle.rs")
        .expect("objectives_lending_oracle source must be readable");
    let deep_source = fs::read_to_string("src/tactics/objectives/objectives_deep_analysis.rs")
        .expect("objectives_deep_analysis source must be readable");

    assert!(
        invariants_source.contains("build_abstract_slot_pair_constraints"),
        "polynomial invariant objective must derive abstract slot-pair constraints"
    );
    assert!(
        invariants_source.contains("POLYNOMIAL_SLOT_RANGE_UPPER_BOUND"),
        "polynomial invariant objective must bound slot search with a range constraint"
    );
    assert!(
        invariants_source.contains("selected_slot_touched_constraint"),
        "polynomial invariant objective must tie abstract slots to touched storage writes"
    );
    assert!(
        lending_source.contains("owner_slot_in_range"),
        "initialization-race objective must use owner-slot range constraints"
    );
    assert!(
        deep_source.contains("owner_slot_in_range"),
        "deep state-transition objective must use owner-slot range constraints"
    );
    assert!(
        !lending_source.contains("slot._eq(&low_slots[0])"),
        "hardcoded owner-slot equality lists must be removed from initialization-race proof"
    );
    assert!(
        !deep_source.contains("slot._eq(&low_slots[0])"),
        "hardcoded owner-slot equality lists must be removed from deep transition proof"
    );
}
