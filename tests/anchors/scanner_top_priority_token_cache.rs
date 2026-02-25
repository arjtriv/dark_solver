use std::fs;

#[test]
fn test_scanner_top_priority_tokens_are_cached_per_chain() {
    let source = fs::read_to_string("src/scanner.rs").expect("read scanner.rs");
    assert!(
        source.contains("fn top_priority_tokens(chain_id: u64) -> Vec<Address>"),
        "scanner must expose top_priority_tokens helper"
    );
    assert!(
        source.contains("static CACHE: OnceLock<DashMap<u64, Vec<Address>>>")
            && source.contains("if let Some(hit) = cache.get(&chain_id)")
            && source.contains("cache.insert(chain_id, tokens.clone())"),
        "top_priority_tokens must memoize token lists per chain id"
    );
}
