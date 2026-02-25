use std::fs;

#[test]
fn background_solver_queue_is_wired_as_low_priority_deep_path() {
    let main_source =
        fs::read_to_string("src/main.rs").expect("src/main.rs must be readable for anchor");
    let catalog_source = fs::read_to_string("src/engine/objective_catalog.rs")
        .expect("src/engine/objective_catalog.rs must be readable for anchor");

    assert!(
        main_source.contains("struct BackgroundSolveTask"),
        "main must define a background deep-solve task payload"
    );
    assert!(
        main_source.contains("load_background_solver_queue_enabled"),
        "main must expose a background queue feature gate"
    );
    assert!(
        main_source.contains("build_background_deep_objectives"),
        "background workers must use deep-only objective catalog builder"
    );
    assert!(
        main_source
            .contains("try_send(\n                                        BackgroundSolveTask"),
        "primary target path must enqueue deep tasks without blocking"
    );
    assert!(
        main_source.contains("is_background: true"),
        "background findings must be tagged as background solve outputs"
    );
    assert!(
        main_source.contains("if res.is_background"),
        "solve telemetry must classify background findings separately"
    );
    assert!(
        catalog_source.contains("pub fn build_background_deep_objectives"),
        "objective catalog must expose deep-only objective builder"
    );
}
