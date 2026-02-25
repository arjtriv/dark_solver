use std::fs;

#[test]
fn test_stealth_vault_env_is_wired_for_single_eoa_and_min_balance_gate() {
    let cfg = fs::read_to_string("src/utils/config.rs")
        .expect("src/utils/config.rs must be readable for stealth vault audit");
    assert!(
        cfg.contains("STEALTH_VAULT_PRIVATE_KEY"),
        "config must support STEALTH_VAULT_PRIVATE_KEY override"
    );
    assert!(
        cfg.contains("STEALTH_VAULT_MIN_BALANCE_WEI"),
        "config must support STEALTH_VAULT_MIN_BALANCE_WEI guard"
    );

    let exec = fs::read_to_string("src/executor/mod.rs")
        .expect("src/executor/mod.rs must be readable for stealth vault audit");
    assert!(
        exec.contains("stealth_vault_min_balance_wei"),
        "executor must store stealth vault min-balance setting"
    );
    assert!(
        exec.contains("[VAULT] Stealth vault balance too low"),
        "executor must fail-closed when vault balance is below threshold"
    );
}
