//! Symbolic memoization cache for bytecode-level proof reuse.
//!
//! Many protocol forks (for example, Uniswap V2-style clones) share nearly identical bytecode.
//! This module caches symbolic proof results by bytecode fingerprint + function selector
//! so the solver can reuse prior results instead of re-proving identical paths.
//!
//! Architecture:
//! - **Fingerprint**: SHA256 hash of bytecode with constructor args stripped (last 64 bytes)
//! - **Cache Key**: (Fingerprint, Selector)
//! - **Cache Value**: ProofResult (SAT with params, UNSAT, or TIMEOUT)
//! - **Thread Safety**: DashMap for low-contention concurrent reads/writes across solver workers

use dashmap::DashMap;
use revm::primitives::{Bytes, U256};
use std::sync::LazyLock;

use crate::storage::contracts_db::ContractsDb;

/// Global proof cache shared across solver workers.
/// `LazyLock` keeps initialization deferred until first use.
static PROOF_CACHE: LazyLock<DashMap<(BytecodeFingerprint, SelectorKey), ProofResult>> =
    LazyLock::new(|| DashMap::with_capacity(4096));

// Unit tests must be hermetic: never read/write the on-disk proof cache (it can leak state across
// runs and make tests flaky/non-deterministic).
#[cfg(not(test))]
static PROOF_CACHE_DB: LazyLock<Option<ContractsDb>> =
    LazyLock::new(|| ContractsDb::open_default().ok());
#[cfg(test)]
static PROOF_CACHE_DB: LazyLock<Option<ContractsDb>> = LazyLock::new(|| None);

/// SHA256-based bytecode fingerprint.
/// We strip the last 64 bytes (constructor args) to normalize forks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BytecodeFingerprint([u8; 32]);

/// 4-byte function selector used as part of the cache key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SelectorKey([u8; 4]);

/// Cached result of a symbolic proof for a specific (bytecode, selector) pair.
#[derive(Debug, Clone)]
pub enum ProofResult {
    /// Solver found a satisfying assignment (potential exploit).
    /// We store the flash loan amount and expected profit for quick replay.
    Sat {
        flash_loan_amount: U256,
        expected_profit: Option<U256>,
    },
    /// Solver proved UNSAT — no exploit exists for this selector on this bytecode.
    Unsat,
    /// Solver timed out — inconclusive, should retry with different strategy.
    Timeout,
}

impl BytecodeFingerprint {
    /// Compute fingerprint from bytecode.
    ///
    /// Strategy: Hash the "code body" — strip the last 64 bytes which are typically
    /// constructor arguments (2x 32-byte ABI-encoded params). This makes forks of the
    /// same contract produce identical fingerprints.
    ///
    /// For very short bytecodes (< 128 bytes), we hash the entire thing.
    pub fn from_bytecode(bytecode: &Bytes) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let bytes = bytecode.as_ref();
        // Strip constructor args (last 64 bytes) for normalization
        let body = if bytes.len() > 128 {
            &bytes[..bytes.len() - 64]
        } else {
            bytes
        };

        // Use a fast non-crypto hash for cache keying (correctness doesn't depend on collision resistance)
        let mut hasher = DefaultHasher::new();
        body.hash(&mut hasher);
        let h1 = hasher.finish();

        // Double-hash for lower collision probability
        let mut hasher2 = DefaultHasher::new();
        h1.hash(&mut hasher2);
        body.len().hash(&mut hasher2);
        let h2 = hasher2.finish();

        let mut fp = [0u8; 32];
        fp[..8].copy_from_slice(&h1.to_le_bytes());
        fp[8..16].copy_from_slice(&h2.to_le_bytes());
        fp[16..24].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        // Remaining 8 bytes are zero — reserved for future versioning
        Self(fp)
    }
}

impl SelectorKey {
    pub fn from_bytes(selector: &Bytes) -> Option<Self> {
        if selector.len() >= 4 {
            let mut key = [0u8; 4];
            key.copy_from_slice(&selector[..4]);
            Some(Self(key))
        } else if selector.is_empty() {
            // Fallback/receive function
            Some(Self([0u8; 4]))
        } else {
            None
        }
    }
}

fn fingerprint_hex(fp: &BytecodeFingerprint) -> String {
    format!("0x{}", hex::encode(fp.0))
}

fn selector_hex(sk: &SelectorKey) -> String {
    format!("0x{}", hex::encode(sk.0))
}

/// Look up a cached proof result for a given bytecode + selector.
pub fn lookup(bytecode: &Bytes, selector: &Bytes) -> Option<ProofResult> {
    let fp = BytecodeFingerprint::from_bytecode(bytecode);
    let sk = SelectorKey::from_bytes(selector)?;
    if let Some(value) = PROOF_CACHE.get(&(fp.clone(), sk.clone())) {
        return Some(value.value().clone());
    }

    if let Some(db) = PROOF_CACHE_DB.as_ref() {
        let fp_hex = fingerprint_hex(&fp);
        let sk_hex = selector_hex(&sk);
        if let Ok(Some(result)) = db.lookup_proof_cache(&fp_hex, &sk_hex) {
            PROOF_CACHE.insert((fp, sk), result.clone());
            return Some(result);
        }
    }

    None
}

/// Store a proof result in the cache.
pub fn store(bytecode: &Bytes, selector: &Bytes, result: ProofResult) {
    let fp = BytecodeFingerprint::from_bytecode(bytecode);
    if let Some(sk) = SelectorKey::from_bytes(selector) {
        PROOF_CACHE.insert((fp.clone(), sk.clone()), result.clone());
        if let Some(db) = PROOF_CACHE_DB.as_ref() {
            let fp_hex = fingerprint_hex(&fp);
            let sk_hex = selector_hex(&sk);
            let _ = db.upsert_proof_cache(&fp_hex, &sk_hex, &result);
        }
    }
}

/// Store UNSAT results for all selectors in a bytecode at once (batch invalidation).
pub fn store_unsat_batch(bytecode: &Bytes, selectors: &[Bytes]) {
    let fp = BytecodeFingerprint::from_bytecode(bytecode);
    for sel in selectors {
        if let Some(sk) = SelectorKey::from_bytes(sel) {
            PROOF_CACHE.insert((fp.clone(), sk.clone()), ProofResult::Unsat);
            if let Some(db) = PROOF_CACHE_DB.as_ref() {
                let fp_hex = fingerprint_hex(&fp);
                let sk_hex = selector_hex(&sk);
                let _ = db.upsert_proof_cache(&fp_hex, &sk_hex, &ProofResult::Unsat);
            }
        }
    }
}

/// Get current cache size (for diagnostics).
pub fn cache_size() -> usize {
    PROOF_CACHE.len()
}

/// Clear entire cache (useful on chain reorg).
pub fn clear_cache() {
    PROOF_CACHE.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_stability() {
        let bc1 = Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15]);
        let bc2 = Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15]);
        assert_eq!(
            BytecodeFingerprint::from_bytecode(&bc1),
            BytecodeFingerprint::from_bytecode(&bc2)
        );
    }

    #[test]
    fn test_fork_normalization() {
        // Two "forks" with same body but different constructor args (last 64 bytes)
        let mut body = vec![0x60u8; 200];
        let bc1 = {
            let mut b = body.clone();
            b.extend_from_slice(&[0xAA; 64]); // Constructor args variant A
            Bytes::from(b)
        };
        let bc2 = {
            body.extend_from_slice(&[0xBB; 64]); // Constructor args variant B
            Bytes::from(body)
        };
        assert_eq!(
            BytecodeFingerprint::from_bytecode(&bc1),
            BytecodeFingerprint::from_bytecode(&bc2),
            "Forks with identical bodies but different constructor args should have same fingerprint"
        );
    }

    #[test]
    fn test_cache_roundtrip() {
        let bc = Bytes::from_static(&[0x60, 0x80, 0x60, 0x40]);
        let sel = Bytes::from_static(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer

        // Initially empty
        assert!(lookup(&bc, &sel).is_none());

        // Store UNSAT
        store(&bc, &sel, ProofResult::Unsat);
        let result = lookup(&bc, &sel);
        assert!(matches!(result, Some(ProofResult::Unsat)));

        // Overwrite with SAT
        store(
            &bc,
            &sel,
            ProofResult::Sat {
                flash_loan_amount: U256::from(1000),
                expected_profit: Some(U256::from(50)),
            },
        );
        let result = lookup(&bc, &sel);
        assert!(matches!(result, Some(ProofResult::Sat { .. })));

        // Cleanup
        clear_cache();
    }
}
