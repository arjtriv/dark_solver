use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn compact_binary_logs_enabled() -> bool {
    std::env::var("COMPACT_BINARY_LOGS_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Append a framed record: `[u32_le length][payload bytes...]`.
pub fn append_framed(path: &Path, payload: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| std::io::Error::other("binary frame too large"))?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&len.to_le_bytes())?;
    file.write_all(payload)?;
    Ok(())
}

pub fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

pub fn write_f64_le(out: &mut Vec<u8>, value: f64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(if value { 1 } else { 0 });
}

pub fn write_opt_f64_le(out: &mut Vec<u8>, value: Option<f64>) {
    match value {
        Some(v) => {
            write_u8(out, 1);
            write_f64_le(out, v);
        }
        None => write_u8(out, 0),
    }
}

pub fn write_string(out: &mut Vec<u8>, value: &str) -> std::io::Result<()> {
    let bytes = value.as_bytes();
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| std::io::Error::other("string too large"))?;
    write_u32_le(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

pub trait BinaryEncode {
    fn encode_binary(&self) -> std::io::Result<Vec<u8>>;
}

pub fn append_framed_encoded<T: BinaryEncode>(path: &Path, record: &T) -> std::io::Result<()> {
    let payload = record.encode_binary()?;
    append_framed(path, &payload)
}
