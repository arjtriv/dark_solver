pub fn compact_error_message(message: &str, max_len: usize) -> String {
    let mut raw = message.to_string();
    if let Some((prefix, _)) = raw.split_once(" text: ") {
        raw = format!("{prefix} text=<omitted>");
    }
    if let Some((prefix, _)) = raw.split_once("Stack backtrace:") {
        raw = prefix.to_string();
    }

    let mut compact = String::with_capacity(raw.len().min(max_len.saturating_add(16)));
    let mut prev_ws = false;
    for ch in raw.chars() {
        if ch.is_whitespace() {
            if !prev_ws && !compact.is_empty() {
                compact.push(' ');
            }
            prev_ws = true;
            continue;
        }
        compact.push(ch);
        prev_ws = false;
        if compact.len() > max_len {
            break;
        }
    }
    if compact.len() <= max_len {
        compact
    } else {
        compact.truncate(max_len);
        compact.push_str("...(truncated)");
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::compact_error_message;

    #[test]
    fn test_compact_error_message_elides_payload_and_backtrace() {
        let raw = "DeserError { err: unknown variant `0x7e`, text: \"{...huge...}\" }\nStack backtrace:\n 0: frame";
        let compact = compact_error_message(raw, 260);
        assert!(compact.contains("text=<omitted>"));
        assert!(!compact.contains("Stack backtrace"));
    }
}
