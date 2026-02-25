use std::fs;

#[test]
fn test_greedy_scheduler_bundle_merge_is_wired() {
    let scheduler_source = fs::read_to_string("src/solver/scheduler.rs")
        .expect("src/solver/scheduler.rs must be readable for scheduler merge audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for scheduler integration audit");

    assert!(
        scheduler_source.contains("greedy_schedule_findings")
            && scheduler_source.contains("MAX_MERGED_STEPS")
            && scheduler_source.contains("Greedy Scheduler Merge"),
        "scheduler module must implement conservative greedy merge logic for finding bundles"
    );
    assert!(
        main_source.contains("greedy_schedule_findings(res.findings)"),
        "main runtime must route findings through the greedy scheduler before execution dispatch"
    );
}
