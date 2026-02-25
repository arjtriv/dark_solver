use std::fs;

#[test]
fn test_interest_rate_model_gaming_objective_is_wired_and_solver_gated() {
    let objective_source = crate::anchor_utils::read_objectives_source();
    let protocol_source = fs::read_to_string("src/protocols/interest_rate.rs")
        .expect("src/protocols/interest_rate.rs must be readable for interest-rate protocol audit");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for objective wiring audit");

    assert!(
        objective_source.contains("pub struct InterestRateModelGamingObjective"),
        "solver must expose InterestRateModelGamingObjective"
    );
    assert!(
        objective_source.contains("build_interest_rate_gaming_steps"),
        "interest-rate objective must build a bounded multi-step plan"
    );
    assert!(
        objective_source.contains("is_insolvent"),
        "interest-rate objective must enforce insolvency gate on final state"
    );
    assert!(
        protocol_source.contains("rate_drop_exceeds_bps"),
        "interest-rate protocol helper must enforce borrow-rate crash predicate"
    );
    assert!(
        catalog_source.contains("InterestRateModelGamingObjective"),
        "objective catalog must include InterestRateModelGamingObjective"
    );
}
