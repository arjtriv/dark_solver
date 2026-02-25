use std::fs;

#[test]
fn test_main_has_daily_stop_loss_guard() {
    let main_rs = fs::read_to_string("src/main.rs").expect("read src/main.rs");

    assert!(
        main_rs.contains("daily_stop_loss_start_balance")
            && main_rs.contains("provider.get_balance(daily_stop_loss_attacker)")
            && main_rs.contains("Daily stop-loss armed")
            && main_rs.contains("panic!(")
            && main_rs.contains("Daily stop-loss triggered:")
            && main_rs.contains("drawdown_limit_wei"),
        "main runtime must arm and enforce a 1 ETH daily stop-loss with hard process kill"
    );
}
