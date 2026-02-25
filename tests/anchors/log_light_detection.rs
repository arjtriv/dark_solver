use std::fs;

#[test]
fn test_log_light_detection_mode_is_wired() {
    let src =
        fs::read_to_string("src/scanner.rs").expect("src/scanner.rs must be readable for audit");

    assert!(
        src.contains("SCAN_LOG_LIGHT_ENABLED"),
        "scanner must support SCAN_LOG_LIGHT_ENABLED toggle"
    );
    assert!(
        src.contains("subscribe_logs"),
        "scanner must subscribe to logs in light mode"
    );
    assert!(
        src.contains("Swap(address,uint256,uint256,uint256,uint256,address)"),
        "light mode must include UniswapV2 Swap topic signature"
    );
    assert!(
        src.contains("Swap(address,address,int256,int256,uint160,uint128,int24)"),
        "light mode must include UniswapV3 Swap topic signature"
    );
}
