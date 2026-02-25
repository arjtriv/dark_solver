// Minimal SimHash utilities for bytecode locality detection.
//
// This is intentionally simple, deterministic, and dependency-free. It is used as a
// best-effort throughput optimization (never for safety-critical correctness).

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001B3;

#[inline]
fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Computes a 64-bit SimHash over the raw byte stream using fixed-size shingles.
pub fn simhash64(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }

    let mut acc = [0i32; 64];
    const WINDOW: usize = 8;
    const STRIDE: usize = 4;

    let mut i = 0usize;
    while i + WINDOW <= bytes.len() {
        let mut h = fnv1a64(FNV_OFFSET_BASIS, &bytes[i..i + WINDOW]);
        // Mix in position to reduce collisions on repeated blocks.
        h ^= (i as u64).wrapping_mul(0x9e3779b97f4a7c15);
        for (bit, slot) in acc.iter_mut().enumerate() {
            if ((h >> bit) & 1) == 1 {
                *slot += 1;
            } else {
                *slot -= 1;
            }
        }
        i += STRIDE;
    }

    // Tail feature (if any) so short bytecode still contributes.
    if i < bytes.len() {
        let h = fnv1a64(FNV_OFFSET_BASIS ^ 0xdeadbeefcafebabe, &bytes[i..]);
        for (bit, slot) in acc.iter_mut().enumerate() {
            if ((h >> bit) & 1) == 1 {
                *slot += 1;
            } else {
                *slot -= 1;
            }
        }
    }

    let mut out = 0u64;
    for (bit, score) in acc.iter().enumerate() {
        if *score >= 0 {
            out |= 1u64 << bit;
        }
    }
    out
}

#[inline]
pub fn hamming_distance64(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

#[inline]
pub fn simhash_hex(simhash: u64) -> String {
    format!("0x{simhash:016x}")
}

pub fn parse_simhash_hex(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(hex, 16).ok()
}

#[inline]
pub fn simhash_bands16(simhash: u64) -> [u16; 4] {
    [
        (simhash & 0xffff) as u16,
        ((simhash >> 16) & 0xffff) as u16,
        ((simhash >> 32) & 0xffff) as u16,
        ((simhash >> 48) & 0xffff) as u16,
    ]
}
