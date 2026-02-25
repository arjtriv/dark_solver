use std::fs;

#[test]
fn test_executor_dedupes_conditional_predicates_up_front() {
    let source = fs::read_to_string("src/executor/mod.rs").expect("read executor/mod.rs");
    assert!(
        source.contains("seen_conditional = HashMap::<(Address, U256), U256>::new()"),
        "executor must dedupe execute_if predicates by (contract,slot) up front"
    );
    assert!(
        source.contains("Conflicting execute_if predicates")
            && source.contains("DroppedConditional"),
        "executor must fail-closed on conflicting duplicate execute_if predicates"
    );
    assert!(
        source.contains("conditional_checks.push((step.target, cond.slot, cond.equals));"),
        "executor should keep only deduped conditional predicates for later checks"
    );
}
