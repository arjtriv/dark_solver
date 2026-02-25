use std::fs;

fn find_required(content: &str, needle: &str) -> usize {
    match content.find(needle) {
        Some(idx) => idx,
        None => panic!("missing required replay gate fragment: {needle}"),
    }
}

fn guard_block<'a>(content: &'a str, guard_idx: usize, guard_label: &str) -> &'a str {
    let open_rel = content[guard_idx..]
        .find('{')
        .unwrap_or_else(|| panic!("missing opening brace for guard: {guard_label}"));
    let open_idx = guard_idx + open_rel;

    let mut depth = 0usize;
    for (offset, ch) in content[open_idx..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return &content[open_idx..=open_idx + offset];
                }
            }
            _ => {}
        }
    }

    panic!("missing closing brace for guard: {guard_label}");
}

#[test]
fn test_executor_enforces_shadow_replay_before_bundle_send() {
    let source = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for replay gate audit");

    let replay_idx = find_required(&source, "let shadow_report =");
    let success_guard_idx = find_required(&source, "if !shadow_report.success");
    let profit_guard_idx = find_required(&source, "if !shadow_report.profitable");
    let send_bundle_idx = find_required(&source, ".send_bundle_ranked(&bundle, &ranked_builders)");

    assert!(
        replay_idx < success_guard_idx,
        "shadow replay must occur before success guard"
    );
    assert!(
        success_guard_idx < profit_guard_idx,
        "success guard must be evaluated before profitability guard"
    );
    assert!(
        profit_guard_idx < send_bundle_idx,
        "bundle submission must not happen before replay guards"
    );

    let success_tail = guard_block(&source, success_guard_idx, "if !shadow_report.success");
    assert!(
        success_tail.contains("return feedback;"),
        "failed shadow replay path must hard-return before bundle submission"
    );
    assert!(
        !success_tail.contains(".send_bundle_ranked(&bundle, &ranked_builders)"),
        "failed shadow replay branch must never include bundle submission"
    );

    let profit_tail = guard_block(&source, profit_guard_idx, "if !shadow_report.profitable");
    assert!(
        profit_tail.contains("return feedback;"),
        "unprofitable shadow replay path must hard-return before bundle submission"
    );
    assert!(
        !profit_tail.contains(".send_bundle_ranked(&bundle, &ranked_builders)"),
        "unprofitable shadow replay branch must never include bundle submission"
    );
}
