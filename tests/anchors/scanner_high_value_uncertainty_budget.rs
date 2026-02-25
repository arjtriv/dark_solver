use std::fs;

#[test]
fn test_scanner_high_value_uncertainty_budget_is_wired() {
    let scanner = fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable");

    assert!(
        scanner.contains("SCAN_HIGH_VALUE_UNKNOWN_ADMIT_BUDGET_PER_MIN")
            && scanner.contains("SCAN_HIGH_VALUE_UNKNOWN_ADMIT_COOLDOWN_MS")
            && scanner.contains("allow_high_value_unknown_admission"),
        "scanner high-value gate must expose bounded uncertainty-admit controls"
    );
    assert!(
        scanner.contains("High-value admission uncertainty override")
            && scanner.contains("uncertain_due_to_provider_pressure"),
        "scanner must classify provider-pressure uncertainty and apply bounded override path"
    );
}
