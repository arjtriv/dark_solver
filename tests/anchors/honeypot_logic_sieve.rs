//! Anchor: honey-pot logic sieve persists admin-key-required selectors and filters them.

use dark_solver::solver::honeypot::{
    is_admin_key_required_revert, is_honeypot_selector, record_admin_key_required,
};
use dark_solver::storage::contracts_db::ContractsDb;
use revm::primitives::{Address, Bytes};

#[test]
fn honeypot_logic_sieve_detects_owner_revert_strings() {
    assert!(is_admin_key_required_revert(
        "Ownable: caller is not the owner"
    ));
    assert!(is_admin_key_required_revert(
        "AccessControl: account is missing role"
    ));
}

#[test]
fn honeypot_logic_sieve_persists_and_filters_selectors() {
    // Use a temp DB so the test is isolated.
    let path = std::env::temp_dir().join(format!("dark_solver_honeypot_{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let db = ContractsDb::open(&path).expect("db open");

    // Seed a honeypot selector via DB upsert to prove the lookup path.
    let contract = Address::from([0x11; 20]);
    let call = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x01]);
    let selector = [0xde, 0xad, 0xbe, 0xef];
    let entry = dark_solver::solver::honeypot::HoneypotEntry {
        contract,
        selector,
        class: dark_solver::solver::honeypot::HoneypotClass::AdminKeyRequired,
        reason: "Ownable: caller is not the owner".to_string(),
    };
    db.upsert_honeypot_sieve(&entry).expect("upsert honeypot");
    let loaded = db
        .lookup_honeypot_sieve(contract, selector)
        .expect("lookup ok")
        .expect("must exist");
    assert_eq!(loaded.selector, selector);

    // Verify in-memory filter can be primed, and the classifier remains correct.
    record_admin_key_required(contract, &call, "Ownable: caller is not the owner");
    assert!(is_honeypot_selector(contract, &call));
}
