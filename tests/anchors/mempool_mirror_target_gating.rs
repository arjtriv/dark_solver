use std::fs;

#[test]
fn mempool_mirror_path_is_target_gated_and_attacker_mirrored() {
    let strategy = fs::read_to_string("src/strategies/generalized_frontrun.rs")
        .expect("src/strategies/generalized_frontrun.rs must be readable");

    assert!(
        strategy.contains("GENERALIZED_FRONTRUN_REQUIRE_TRACKED_TARGET")
            && strategy.contains("GENERALIZED_FRONTRUN_MIN_TARGET_TVL_WEI")
            && strategy.contains("mirror_target_allowed(")
            && strategy.contains("target_capital_estimate_eth_wei")
            && strategy.contains("executor.attacker_address()")
            && strategy.contains("subscribe_full_pending_transactions")
            && strategy.contains("execute_attack("),
        "strategy must mirror pending sequencer txs as attacker-local execution and gate on tracked targets"
    );
}
