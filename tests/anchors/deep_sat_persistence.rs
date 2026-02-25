use std::fs;

#[test]
fn sat_genome_persistence_and_late_solve_protocol_are_wired() {
    let main_source = fs::read_to_string("src/main.rs").expect("main source must be readable");

    let persist_call = "record_vulnerable_genome(res.bytecode_hash, res.target)";
    let execute_call = "execute_attack(";

    let persist_idx = main_source
        .find(persist_call)
        .expect("main must persist SAT genomes in findings consumer path");
    let execute_idx = main_source
        .find(execute_call)
        .expect("main must still dispatch findings to executor");

    assert!(
        persist_idx < execute_idx,
        "SAT persistence must happen before executor dispatch"
    );
    assert!(
        !main_source.contains("[PERF_GATE] Dropping"),
        "late-solve protocol should replace hard 1800ms dropping"
    );
    assert!(
        main_source.contains("require_late_solve_preflight"),
        "main must compute and pass late-solve preflight trigger"
    );
    assert!(
        main_source.contains("solve_time > 2_000 || solve_time > block_time_ms"),
        "late-solve protocol must trigger on 2000ms or chain block-time threshold"
    );
    assert!(
        main_source.contains("bytecode_hash: B256"),
        "SolverResult must carry bytecode hash for no-drop-zone persistence"
    );
}
