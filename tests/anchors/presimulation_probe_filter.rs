use std::fs;

#[test]
fn test_presimulation_probe_filter_is_wired() {
    let heuristics_source = fs::read_to_string("src/solver/heuristics.rs")
        .expect("src/solver/heuristics.rs must be readable for pre-simulation probe audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for pre-sim gating audit");

    assert!(
        heuristics_source.contains("run_pre_simulation_probe")
            && heuristics_source.contains("PRE_SIM_PROBE_ENABLED")
            && heuristics_source.contains("PRE_SIM_PROBE_STRICT")
            && heuristics_source.contains("eth_call"),
        "heuristics layer must provide bounded concrete pre-simulation probes over transfer/approve calls"
    );
    assert!(
        main_source.contains("run_pre_simulation_probe")
            && main_source.contains("Target {:?} filtered by concrete probe"),
        "solver intake path must run pre-simulation probes and filter anomalous targets before heavy solving"
    );
}
