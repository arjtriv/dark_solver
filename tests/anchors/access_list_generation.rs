use std::fs;

#[test]
fn test_eip2930_access_list_generation_is_wired() {
    let access_list = fs::read_to_string("src/executor/access_list.rs")
        .expect("read src/executor/access_list.rs");
    let executor = fs::read_to_string("src/executor/mod.rs").expect("read src/executor/mod.rs");

    assert!(
        access_list.contains("ACCESS_LIST_ENABLED")
            && access_list.contains("ACCESS_LIST_STRICT")
            && access_list.contains("ACCESS_LIST_TIMEOUT_MS")
            && access_list.contains("ACCESS_LIST_TOTAL_BUDGET_MS")
            && access_list.contains("ACCESS_LIST_MAX_TXS_PER_GROUP")
            && access_list.contains("ACCESS_LIST_MAX_ITEMS")
            && access_list.contains("ACCESS_LIST_MAX_KEYS_PER_ITEM")
            && access_list.contains("create_access_list")
            && access_list.contains(".pending()"),
        "executor must support bounded eth_createAccessList(pending) generation with env clamps"
    );

    assert!(
        executor.contains("maybe_attach_access_list_best_effort")
            && executor.contains("[ACCESSLIST] Attached"),
        "executor signing loop must attempt to attach access lists when enabled"
    );
}
