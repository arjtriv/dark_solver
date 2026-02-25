use std::fs;

#[test]
fn manual_target_must_bypass_done_gate() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for manual-target override audit");

    assert!(
        main_source.contains("manual_target_override"),
        "main loop must compute manual target override flag"
    );
    assert!(
        main_source.contains("Ok(true) if !manual_target_override => {")
            && main_source.contains("continue;"),
        "done gate must only skip non-manual targets"
    );
    assert!(
        main_source.contains("forcing re-run due to manual override"),
        "manual done override path must be explicit in logs"
    );
}
