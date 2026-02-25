use std::fs;

#[test]
fn test_builder_reliability_routing_is_wired() {
    let executor_source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for builder-routing audit");
    let builders_source = fs::read_to_string("src/executor/builders.rs")
        .expect("src/executor/builders.rs must be readable for builder-routing audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for builder-routing audit");

    assert!(
        executor_source.contains("builder_routing_stats(BUILDER_ROUTING_SAMPLE_LIMIT)"),
        "executor must load rolling builder routing stats from persistence"
    );
    assert!(
        executor_source.contains("send_bundle_ranked(&bundle, &ranked_builders)"),
        "executor must route bundle dispatch via ranked builder ordering"
    );
    assert!(
        executor_source.contains("ranked_builders_from_db"),
        "executor must derive dynamic builder order from persisted reliability metrics"
    );
    assert!(
        builders_source.contains("pub async fn send_bundle_ranked"),
        "multibuilder must expose ranked dispatch path"
    );
    assert!(
        storage_source.contains("pub fn builder_routing_stats"),
        "storage layer must expose rolling builder routing metrics"
    );
}
