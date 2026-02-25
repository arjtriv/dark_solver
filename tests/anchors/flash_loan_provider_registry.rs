use std::fs;

#[test]
fn test_flash_loan_provider_registry_is_wired_to_solver_and_primary_selection() {
    let setup_source = fs::read_to_string("src/solver/setup.rs")
        .expect("src/solver/setup.rs must be readable for flash-loan provider registry anchor");
    let objective_source = fs::read_to_string("src/tactics/objectives/objectives_tail_and_tests.rs")
        .expect("src/tactics/objectives/objectives_tail_and_tests.rs must be readable for flash-loan provider registry anchor");

    assert!(
        setup_source.contains("get_default_providers(chain_id)")
            && setup_source.contains("modeled_flash_loan_provider_fees"),
        "solver setup must source modeled flash-loan legs from get_default_providers(chain_id)"
    );
    assert!(
        objective_source.contains("choose_primary_flash_loan_source")
            && objective_source.contains("fee_bps")
            && objective_source.contains("unwrap_or((Address::ZERO, Address::ZERO))"),
        "objective solver must select a concrete primary provider from modeled legs instead of unconditional zero-provider fallback"
    );
}
