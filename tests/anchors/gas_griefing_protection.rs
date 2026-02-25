//! Anchor: gas-griefing protection persists OutOfGas / revert-cost traps and filters selectors.

use dark_solver::solver::gas_grief::{
    classify_shadow_failure, is_gas_grief_selector, record_gas_grief, GasGriefClass, GasGriefEntry,
    ShadowFailureReport,
};
use dark_solver::storage::contracts_db::ContractsDb;
use revm::primitives::{Address, Bytes};

#[test]
fn gas_griefing_protection_classifies_out_of_gas_halts() {
    let report = ShadowFailureReport {
        success: false,
        failure_gas_used: Some(2_000_000),
        failure_gas_limit: Some(2_000_000),
        halt_reason: Some("OutOfGas".to_string()),
    };
    let (class, _reason, _gas_used, _gas_limit) =
        classify_shadow_failure(&report).expect("must classify");
    assert_eq!(class, GasGriefClass::OutOfGas);
}

#[test]
fn gas_griefing_protection_persists_and_filters_selectors() {
    // Use a temp DB so the test is isolated.
    let path =
        std::env::temp_dir().join(format!("dark_solver_gas_grief_{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let db = ContractsDb::open(&path).expect("db open");

    let contract = Address::from([0x22; 20]);
    let call = Bytes::from_static(&[0xca, 0xfe, 0xba, 0xbe, 0x01]);
    let selector = [0xca, 0xfe, 0xba, 0xbe];
    let entry = GasGriefEntry {
        contract,
        selector,
        class: GasGriefClass::OutOfGas,
        reason: "halt=OutOfGas".to_string(),
        gas_used: 2_000_000,
        gas_limit: 2_000_000,
    };
    db.upsert_gas_grief_sieve(&entry).expect("upsert");
    let loaded = db
        .lookup_gas_grief_sieve(contract, selector)
        .expect("lookup ok")
        .expect("must exist");
    assert_eq!(loaded.selector, selector);
    assert_eq!(loaded.class, GasGriefClass::OutOfGas);

    // In-memory filter can be primed even when the default DB isn't used.
    record_gas_grief(
        contract,
        &call,
        GasGriefClass::OutOfGas,
        "halt=OutOfGas",
        2_000_000,
        2_000_000,
    );
    assert!(is_gas_grief_selector(contract, &call));
}
