use std::fs;
use std::path::Path;

#[test]
fn test_proof_cache_db_is_disabled_in_unit_tests() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let memo_source = fs::read_to_string(repo_root.join("src/solver/memo.rs"))
        .expect("src/solver/memo.rs must be readable for proof cache audit");

    assert!(
        memo_source.contains("#[cfg(test)]")
            && memo_source.contains("static PROOF_CACHE_DB")
            && memo_source.contains("LazyLock::new(|| None)"),
        "expected PROOF_CACHE_DB to be disabled under cfg(test) to keep unit tests hermetic"
    );
}
