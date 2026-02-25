//! Anchor Test: bundle obfuscation noise tx policy is enforced.

#[test]
fn test_bundle_obfuscation_noise_count_and_marker() {
    let count = dark_solver::executor::noise_bundle_tx_count();
    assert!(
        (0..=3).contains(&count),
        "noise tx count must stay in [0, 3]"
    );

    let marker0 = dark_solver::executor::build_noise_marker(0, 0, 100);
    let marker1 = dark_solver::executor::build_noise_marker(0, 1, 100);
    assert_ne!(marker0, marker1);
    assert_eq!(marker0.len(), 32);
}
