#[path = "gauntlet/catalog.rs"]
mod catalog;

#[path = "gauntlet/runner.rs"]
mod runner;

use std::time::{Duration, Instant};

#[test]
fn reprove_top_100_historical_exploits_under_one_minute() {
    let started = Instant::now();
    let cases = catalog::top_100_historical_cases();
    assert_eq!(
        cases.len(),
        100,
        "gauntlet catalog must contain exactly 100 historical exploit cases"
    );

    for case in &cases {
        if let Err(err) = runner::run_case(case) {
            panic!(
                "gauntlet case {} [{} / {}] failed: {}",
                case.id, case.exploit, case.primitive, err
            );
        }
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "gauntlet budget exceeded: {:?} >= 60s",
        elapsed
    );
}
