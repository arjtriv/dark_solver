use std::fs;

#[test]
fn test_native_sqlite_driver_enforced_for_contracts_db() {
    let contracts_db = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for sqlite driver audit");

    assert!(
        contracts_db.contains("use rusqlite"),
        "contracts_db must use native rusqlite driver"
    );

    assert!(
        !contracts_db.contains("Command::new(\"sqlite3\")"),
        "contracts_db must not shell out to sqlite3 CLI"
    );

    assert!(
        !contracts_db.contains("sqlite3"),
        "contracts_db must not depend on sqlite3 CLI strings"
    );
}
