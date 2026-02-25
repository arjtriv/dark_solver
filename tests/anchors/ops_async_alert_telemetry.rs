use std::fs;

#[test]
fn test_ops_async_alert_telemetry_is_wired() {
    let telemetry_source = fs::read_to_string("src/utils/telemetry.rs")
        .expect("src/utils/telemetry.rs must be readable for telemetry audit");
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for telemetry wiring audit");

    assert!(
        telemetry_source.contains("DISCORD_WEBHOOK_URL")
            && telemetry_source.contains("TELEGRAM_BOT_TOKEN")
            && telemetry_source.contains("TELEGRAM_CHAT_ID")
            && telemetry_source.contains("sync_channel")
            && telemetry_source.contains("std::thread::spawn")
            && telemetry_source.contains("emit_success")
            && telemetry_source.contains("emit_critical"),
        "telemetry utility must support async buffered Discord/Telegram event dispatch"
    );
    assert!(
        main_source.contains("init_telemetry")
            && main_source.contains("emit_success(")
            && main_source.contains("emit_critical("),
        "runtime must initialize telemetry and emit success/critical execution signals"
    );
}
