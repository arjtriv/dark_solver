use alloy::primitives::U256;

/// Clean a hex string by removing "0x" prefix and whitespace
pub fn clean_hex(s: &str) -> &str {
    let s = s.trim();
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        s
    }
}

/// Convert a string (hex or decimal) to U256
pub fn to_u256(s: &str) -> Option<U256> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(hex) = s.strip_prefix("0x") {
        return U256::from_str_radix(hex, 16).ok();
    }

    if let Some(hex) = s.strip_prefix("#x") {
        return U256::from_str_radix(hex, 16).ok();
    }

    if let Some(bin) = s.strip_prefix("#b") {
        return U256::from_str_radix(bin, 2).ok();
    }

    if s.chars().all(|c| c.is_ascii_digit()) {
        return U256::from_str_radix(s, 10).ok();
    }

    None
}
