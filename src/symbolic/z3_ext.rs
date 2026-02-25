use alloy::primitives::Address as aAddress;
use revm::primitives::{Address as rAddress, U256};
use z3::{
    ast::{Ast, BV},
    Context, FuncDecl,
};

pub fn u256_from_bv(bv: &BV) -> Option<U256> {
    // Optimization: Let Z3 do the constant folding
    let simplified = bv.simplify();

    // Fast path for small constants
    if let Some(val) = simplified.as_u64() {
        return Some(U256::from(val));
    }

    // Optimization: Avoid string round-trip for concrete values if possible?
    // Z3's C API might allow direct byte extraction but Rust bindings typically rely on as_u64 or to_string.
    // For now, we optimize the parsing logic.

    let s = simplified.to_string();
    crate::utils::hex::to_u256(&s)
}

pub fn bv_from_u256<'ctx>(ctx: &'ctx Context, val: U256) -> BV<'ctx> {
    // Zero-slop conversion: avoid string parsing (BV::from_str) which can fail and silently
    // degrade constants to zero. This is a pure, total mapping from a 256-bit integer to a
    // 256-bit BV via big-endian byte packing.
    let bytes = val.to_be_bytes::<32>();
    let w0 = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let w1 = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let w2 = u64::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
    ]);
    let w3 = u64::from_be_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);

    let bv0 = BV::from_u64(ctx, w0, 64);
    let bv1 = BV::from_u64(ctx, w1, 64);
    let bv2 = BV::from_u64(ctx, w2, 64);
    let bv3 = BV::from_u64(ctx, w3, 64);

    let bv = bv0.concat(&bv1);
    let bv = bv.concat(&bv2);
    bv.concat(&bv3)
}

pub fn address_to_bv<'ctx>(ctx: &'ctx Context, addr: rAddress) -> BV<'ctx> {
    let u = U256::from_be_bytes(addr.into());
    bv_from_u256(ctx, u)
}

pub fn bv_to_address(bv: &BV) -> Option<rAddress> {
    u256_from_bv(bv).map(|u| rAddress::from_slice(&u.to_be_bytes::<32>()[12..]))
}

pub fn alloy_to_revm(addr: aAddress) -> rAddress {
    rAddress::from_slice(addr.as_slice())
}

pub fn revm_to_alloy(addr: rAddress) -> aAddress {
    aAddress::from_slice(addr.as_slice())
}

pub fn configure_solver(ctx: &Context, solver: &z3::Solver) {
    let mut params = z3::Params::new(ctx);
    params.set_u32("timeout", 60000); // 60s
    params.set_u32("rlimit", 200_000_000); // High rlimit
    params.set_bool("model.partial", true);
    params.set_symbol("logic", z3::Symbol::String("QF_ABV".into()));
    params.set_u32("random_seed", 42); // Deterministic by default
    solver.set_params(&params);
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context};

    #[test]
    fn test_u256_from_bv_concat() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // Test case: (concat #x00...01 (_ bv2 128))
        let bv1 = BV::from_u64(&ctx, 1, 128);
        let bv2 = BV::from_u64(&ctx, 2, 128);
        let concat = bv1.concat(&bv2);

        // Z3 simplify() should fold this to #x...
        let val = u256_from_bv(&concat).unwrap();
        // expected: 1 << 128 | 2
        let expected = (U256::from(1) << 128) | U256::from(2);
        assert_eq!(val, expected);

        // Test hex concat
        // (concat #x01 #x02) -> 1 << 8 | 2 = 258
        let hex_bv1 = BV::from_u64(&ctx, 1, 8);
        let hex_bv2 = BV::from_u64(&ctx, 2, 8);
        let hex_concat = hex_bv1.concat(&hex_bv2);
        let val_hex = u256_from_bv(&hex_concat).unwrap();
        assert_eq!(val_hex, U256::from(258));
    }
}

/// The Keccak Theory encapsulates the logic for managing Keccak-256 constraints.
/// It decides whether to use:
/// 1. Uninterpreted Functions (UFs) - for "Black Box" behavior (large inputs, unknown structure).
/// 2. "Sliced" UFs - for specific input sizes (32, 64 bytes) to improve injectivity reasoning.
/// 3. Algebraic Constraints - (Future) for "Glass Box" cracking of small inputs.
pub struct KeccakTheory<'ctx> {
    pub ctx: &'ctx Context,
    pub keccak_256_32: FuncDecl<'ctx>,  // keccak(uint256) -> hash
    pub keccak_256_64: FuncDecl<'ctx>,  // keccak(uint256, uint256) -> hash
    pub keccak_256_96: FuncDecl<'ctx>,  // keccak(uint256, uint256, uint256) -> hash
    pub keccak_256_128: FuncDecl<'ctx>, // keccak(uint256, uint256, uint256, uint256) -> hash
    pub fallback_counter: std::cell::Cell<usize>, // Counter for unique fallback names
}

impl<'ctx> KeccakTheory<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        let domain_addr = z3::Sort::bitvector(ctx, 256);

        // keccak_32(uint256)
        let keccak_256_32 = FuncDecl::new(ctx, "keccak_32", &[&domain_addr], &domain_addr);

        // keccak_64(uint256, uint256)
        let keccak_256_64 = FuncDecl::new(
            ctx,
            "keccak_64",
            &[&domain_addr, &domain_addr],
            &domain_addr,
        );

        // keccak_96(uint256, uint256, uint256)
        let keccak_256_96 = FuncDecl::new(
            ctx,
            "keccak_96",
            &[&domain_addr, &domain_addr, &domain_addr],
            &domain_addr,
        );

        // keccak_128(uint256, uint256, uint256, uint256)
        let keccak_256_128 = FuncDecl::new(
            ctx,
            "keccak_128",
            &[&domain_addr, &domain_addr, &domain_addr, &domain_addr],
            &domain_addr,
        );

        Self {
            ctx,
            keccak_256_32,
            keccak_256_64,
            keccak_256_96,
            keccak_256_128,
            fallback_counter: std::cell::Cell::new(0),
        }
    }

    fn fallback_const(&self) -> BV<'ctx> {
        let id = self.fallback_counter.get();
        self.fallback_counter.set(id + 1);
        let name = format!("keccak_fallback_{}", id);
        BV::new_const(self.ctx, name.as_str(), 256)
    }

    /// Apply the Keccak function to the given inputs.
    /// Uses content-based UFs (not memory-array dependent) for soundness.
    pub fn apply_symbolic(&self, input_values: Option<Vec<BV<'ctx>>>) -> BV<'ctx> {
        // Use size-specific UFs for content-based hashing.
        if let Some(inputs) = input_values {
            match inputs.len() {
                1 => {
                    return self
                        .keccak_256_32
                        .apply(&[&inputs[0]])
                        .as_bv()
                        .unwrap_or_else(|| self.fallback_const());
                }
                2 => {
                    return self
                        .keccak_256_64
                        .apply(&[&inputs[0], &inputs[1]])
                        .as_bv()
                        .unwrap_or_else(|| self.fallback_const())
                }
                3 => {
                    return self
                        .keccak_256_96
                        .apply(&[&inputs[0], &inputs[1], &inputs[2]])
                        .as_bv()
                        .unwrap_or_else(|| self.fallback_const())
                }
                4 => {
                    return self
                        .keccak_256_128
                        .apply(&[&inputs[0], &inputs[1], &inputs[2], &inputs[3]])
                        .as_bv()
                        .unwrap_or_else(|| self.fallback_const())
                }
                _ => {} // Fallback
            }
        }

        // Fallback: fresh symbolic constant per call.
        // Functional consistency for this rare path is handled by lazy injectivity in record_sha3.
        self.fallback_const()
    }

    /// Inject necessary axioms for a new Keccak term if required.
    /// For UFs, this might be injectivity.
    pub fn inject_axioms(&self, _solver: &z3::Solver<'ctx>, _term: &BV<'ctx>) {
        // Placeholder for future bit-blasting or axiom injection
        // Currently handled by lazy injectivity in `state.rs`
    }
    /// Local injectivity projection for an incremental Keccak chain.
    /// If two child hashes are equal, the corresponding parent-hash projection must be equal.
    pub fn verify_injectivity_chain(
        &self,
        solver: &z3::Solver<'ctx>,
        parent_hash: &BV<'ctx>,
        child_hash: &BV<'ctx>,
        other_parent_hash: &BV<'ctx>,
        other_child_hash: &BV<'ctx>,
    ) {
        let child_collision = child_hash._eq(other_child_hash);
        let parent_projection = parent_hash._eq(other_parent_hash);
        solver.assert(&child_collision.implies(&parent_projection));
    }
}

#[cfg(test)]
mod tests_keccak {
    use super::*;
    use z3::{Config, Context, Solver};

    #[test]
    fn test_keccak_theory_slicing() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        configure_solver(&ctx, &solver);
        let theory = KeccakTheory::new(&ctx);

        // 1. Test Sliced UF (32 bytes — 1 word)
        let w1 = BV::from_u64(&ctx, 0xDEADBEEF, 256);
        let hash_sliced = theory.apply_symbolic(Some(vec![w1.clone()]));

        // 2. Test Fallback (no inputs — fresh symbolic constant)
        let hash_generic = theory.apply_symbolic(None);

        // They should be DIFFERENT AST nodes
        assert_ne!(hash_sliced, hash_generic);

        // 3. Test Injectivity Axiom potential (Solve for input)
        // assert(hash_sliced == k(w1))
        // If we assert hash_sliced == X, can we recover w1?
        // (Only if we had inverse axioms, which we don't yet, but we can verify the constraint exists)

        solver.assert(&hash_sliced._eq(&theory.keccak_256_32.apply(&[&w1]).as_bv().unwrap()));
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }
}
