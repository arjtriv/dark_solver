use std::fs;

const AUDITED_FILES: &[&str] = &[
    "src/strategies/storage.rs",
    "src/symbolic/opcodes/calls.rs",
    "src/symbolic/opcodes/context.rs",
    "src/symbolic/opcodes/memory.rs",
    "src/symbolic/patterns.rs",
    "src/symbolic/state.rs",
    "src/symbolic/utils/math.rs",
];

#[test]
fn test_as_u64_extractions_migrated_to_u256_from_bv() {
    let mut violations = Vec::new();
    for path in AUDITED_FILES {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                violations.push(format!("failed to read {path}: {err}"));
                continue;
            }
        };

        for (idx, line) in content.lines().enumerate() {
            if line.contains(".as_u64(") {
                violations.push(format!("{path}:{} still uses .as_u64()", idx + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "as_u64 silent-failure audit failed:\n{}",
        violations.join("\n")
    );
}
