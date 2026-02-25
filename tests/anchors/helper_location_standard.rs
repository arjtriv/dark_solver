use std::fs;
use std::path::{Path, PathBuf};

const CANONICAL_PATH: &str = "src/symbolic/utils/math.rs";

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn test_symbolic_math_helpers_are_centralized_in_math_utils() {
    let math_source = fs::read_to_string(CANONICAL_PATH)
        .expect("src/symbolic/utils/math.rs must be readable for helper-location audit");
    let utils_mod = fs::read_to_string("src/symbolic/utils/mod.rs")
        .expect("src/symbolic/utils/mod.rs must be readable for helper-location audit");

    assert!(
        utils_mod.contains("pub mod math;"),
        "symbolic utils module must expose the canonical math helper location"
    );
    assert!(
        math_source.contains("Canonical location for shared symbolic math helpers."),
        "math helper file must document canonical helper-location policy"
    );

    let canonical_helpers = [
        "pub fn safe_div",
        "pub fn safe_rem",
        "pub fn safe_sdiv",
        "pub fn safe_srem",
        "pub fn extend_to_512",
        "pub fn bounded_len",
        "pub fn symbolic_exp",
        "pub fn symbolic_signextend",
        "pub fn symbolic_byte",
    ];
    for helper in canonical_helpers {
        assert!(
            math_source.contains(helper),
            "canonical math helper missing from src/symbolic/utils/math.rs: {helper}"
        );
    }

    let mut all_rs = Vec::new();
    collect_rs_files(Path::new("src"), &mut all_rs);

    let banned_fragments = [
        "pub fn safe_",
        "pub fn extend_to_512",
        "pub fn bounded_len",
        "pub fn symbolic_exp",
        "pub fn symbolic_signextend",
        "pub fn symbolic_byte",
    ];
    let mut misplaced = Vec::new();
    for path in all_rs {
        let Some(path_str) = path.to_str() else {
            continue;
        };
        if path_str == CANONICAL_PATH {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        if banned_fragments
            .iter()
            .any(|needle| source.contains(needle))
        {
            misplaced.push(path.display().to_string());
        }
    }

    assert!(
        misplaced.is_empty(),
        "math helper-location drift: found helper-like signatures outside {CANONICAL_PATH}: {:?}",
        misplaced
    );
}
