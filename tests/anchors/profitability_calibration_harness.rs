use std::fs;

#[test]
fn test_profitability_calibration_harness_is_wired() {
    let main_source = fs::read_to_string("src/main.rs")
        .expect("src/main.rs must be readable for calibration-harness audit");
    let storage_source = fs::read_to_string("src/storage/contracts_db.rs")
        .expect("src/storage/contracts_db.rs must be readable for calibration-harness audit");

    assert!(
        main_source.contains("recent_calibration_cases")
            && main_source.contains("replay_path_at_block")
            && main_source.contains("calibration_precision_bps"),
        "main runtime must replay archived payloads at historical heads and compute rolling precision"
    );
    assert!(
        main_source.contains("calibration_scored_samples")
            && main_source.contains("ExecutionOutcomeLabel::DroppedPriceConfidence")
            && main_source.contains("CALIBRATION_MIN_PRECISION_BPS"),
        "main runtime must enforce minimum calibrated precision before private submission expansion"
    );
    assert!(
        main_source.contains("payload_json = Some(encode_exploit_params_json")
            && storage_source.contains("payload_json TEXT"),
        "submission attempts must archive deterministic payload JSON for calibration replay"
    );
}
