use std::fs;

#[test]
fn jit_tuner_hot_swaps_background_findings_with_bounded_budget() {
    let main_source =
        fs::read_to_string("src/main.rs").expect("src/main.rs must be readable for jit anchor");

    assert!(
        main_source.contains("load_jit_tuner_enabled"),
        "runtime must expose JIT tuner feature gate"
    );
    assert!(
        main_source.contains("JIT_TUNER_DEFAULT_BUDGET_MS"),
        "runtime must define bounded JIT tuner budget"
    );
    assert!(
        main_source.contains("async fn jit_tune_background_finding"),
        "main must define volatile-field hot-swap tuner"
    );
    assert!(
        main_source.contains("res.is_background && jit_tuner_enabled"),
        "JIT tuner must only run on background SAT findings"
    );
    assert!(
        main_source.contains("jit_tune_background_finding("),
        "findings loop must invoke volatile-field JIT tuning before execution dispatch"
    );
    assert!(
        main_source.contains("replay_path_at_block"),
        "JIT tuner must revalidate candidates against latest head replay"
    );
}
