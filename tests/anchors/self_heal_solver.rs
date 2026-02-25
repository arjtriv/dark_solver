//! Anchor Test: competition rejection signals trigger self-heal eligibility.

#[test]
fn test_self_heal_competition_signal_anchor() {
    assert!(dark_solver::executor::is_competition_rejection_message(
        "replacement transaction underpriced"
    ));
    assert!(dark_solver::executor::is_competition_rejection_message(
        "bundle already imported"
    ));
    assert!(!dark_solver::executor::is_competition_rejection_message(
        "simulation reverted"
    ));
}
