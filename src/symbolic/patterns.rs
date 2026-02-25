use crate::symbolic::state::SymbolicMachine;
use revm::primitives::U256;
use std::collections::HashMap;
use z3::ast::{Ast, BV};

#[derive(Debug, Clone, PartialEq)]
pub enum StoragePattern {
    /// A standard mapping(key => value) where slot = keccak(key . base_slot)
    /// The U256 is the base_slot.
    /// The Option<U256> is the Concrete Key (if recognized).
    FlatMapping(U256, Option<U256>),

    /// A nested mapping(key1 => mapping(key2 => value))
    /// The inner pattern describes the structure of the inner mapping.
    /// The Option<U256> is the Concrete Key for this layer.
    NestedMapping(Box<StoragePattern>, Option<U256>),

    /// A dynamic array uint[] data
    /// Slot = keccak(base_slot) + index
    /// The Option<U256> is the Concrete Index.
    DynamicArray(U256, Option<U256>),

    /// A struct field fixed offset
    /// Base + Offset
    StructField(U256, U256),

    /// Pattern could not be confidently inferred
    Unknown,
}

impl StoragePattern {
    pub fn base_slot(&self) -> Option<U256> {
        match self {
            Self::FlatMapping(b, _) => Some(*b),
            Self::DynamicArray(b, _) => Some(*b),
            Self::NestedMapping(inner, _) => inner.base_slot(),
            Self::StructField(b, _) => Some(*b),
            _ => None,
        }
    }

    pub fn concrete_key(&self) -> Option<U256> {
        match self {
            Self::FlatMapping(_, k) => *k,
            Self::NestedMapping(_, k) => *k,
            Self::DynamicArray(_, k) => *k,
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SHA3Trace<'ctx> {
    /// The input data chunks (usually 32-byte words)
    /// We clamp this to avoid massive vectors. Standard Solidity usage is 2 words (key + slot).
    pub preimage: Vec<BV<'ctx>>,

    /// The resulting symbolic hash (UF application)
    pub hash: BV<'ctx>,

    /// Total size in bytes
    pub size: BV<'ctx>,

    /// Program Counter where this occurred
    pub pc: usize,
}

pub struct PatternInference;

impl PatternInference {
    /// Attempt to infer a storage pattern from a SHA3 operation.
    /// This is heuristics-driven but rooted in Solidity compiler patterns.
    pub fn infer<'ctx>(
        _detected_patterns: Option<&HashMap<U256, StoragePattern>>,
        sha3_traces: &[SHA3Trace<'ctx>],
        trace: &SHA3Trace<'ctx>,
    ) -> Option<StoragePattern> {
        // SOLC Logic:
        // mapping(k => v)  -> keccak(k . slot)     (Size 64)
        // array[]          -> keccak(slot)         (Size 32)

        let size_u64: u64 = crate::symbolic::z3_ext::u256_from_bv(&trace.size)?
            .try_into()
            .ok()?;

        if size_u64 == 64 {
            // Potential Mapping
            // [Key (32), Slot (32)]
            if trace.preimage.len() >= 2 {
                let key_part = &trace.preimage[0];
                let slot_part = &trace.preimage[1];

                // Determine Concrete Key if possible
                let concrete_key = crate::symbolic::z3_ext::u256_from_bv(key_part);

                // Case A: Flat Mapping
                // The slot part is a Concrete Constant <= 256
                if let Some(slot_val) = crate::symbolic::z3_ext::u256_from_bv(slot_part) {
                    if slot_val <= U256::from(256u64) {
                        return Some(StoragePattern::FlatMapping(slot_val, concrete_key));
                    }
                }

                // Case B: Nested Mapping or Array Element
                // If slot_part is NOT a small integer, it is likely a hash from a previous mapping.

                // 1. Try Recursive Lookup in Traces (Symbolic Link)
                // Structural equality on BV works for identical AST nodes
                // We search REVERSE to find the most recent matching hash that generated this slot_part
                if let Some(inner_trace) = sha3_traces.iter().rev().find(|t| t.hash == *slot_part) {
                    // Recurse
                    let inner_pattern = Self::infer(_detected_patterns, sha3_traces, inner_trace)
                        .unwrap_or(StoragePattern::Unknown);
                    return Some(StoragePattern::NestedMapping(
                        Box::new(inner_pattern),
                        concrete_key,
                    ));
                }

                // 2. Try Previous Patterns (Concrete Link)
                // Check if slot_part matches a known concrete pattern
                if let Some(prev_patterns) = _detected_patterns {
                    if let Some(inner_hash) = crate::symbolic::z3_ext::u256_from_bv(slot_part) {
                        if let Some(inner_pattern) = prev_patterns.get(&inner_hash) {
                            return Some(StoragePattern::NestedMapping(
                                Box::new(inner_pattern.clone()),
                                concrete_key,
                            ));
                        }
                    } else {
                        // LIMITATION: If slot_part is symbolic but NOT found in traces, we might be missing context.
                    }
                }

                // Default: If we can't find the inner trace, we assume it's a nested mapping with Unknown base
                return Some(StoragePattern::NestedMapping(
                    Box::new(StoragePattern::Unknown),
                    concrete_key,
                ));
            }
        } else if size_u64 == 32 {
            // Potential Dynamic Array Base
            // keccak(slot)
            if let Some(slot_part) = trace.preimage.first() {
                let concrete_idx = None; // Arrays usually add index AFTER keccak. This is just the base.

                if let Some(slot_val) = crate::symbolic::z3_ext::u256_from_bv(slot_part) {
                    if slot_val <= U256::from(256u64) {
                        return Some(StoragePattern::DynamicArray(slot_val, concrete_idx));
                    }
                }
            }
        }

        None
    }

    /// Generate constraints for Deep Storage Projection.
    /// This handles chains of implications:
    /// If Hash_L3 == Concrete_L3 => Key_L3 == Concrete_Key_L3 AND Hash_L2 == Concrete_L2
    /// => ... => Base_Key == Concrete_Base_Key
    pub fn constrain_deep_projection<'ctx>(
        machine: &SymbolicMachine<'ctx>,
        target_hash: &BV<'ctx>,
        trace: &SHA3Trace<'ctx>,
        pattern: &StoragePattern,
    ) -> Vec<z3::ast::Bool<'ctx>> {
        let mut constraints = Vec::new();
        let target_base = pattern.base_slot();

        // Iterate over all known CONCRETE patterns
        for (concrete_hash_u256, concrete_pattern) in &machine.detected_patterns {
            // 1. Filter by Base Slot (Must Match)
            if concrete_pattern.base_slot() != target_base {
                continue;
            }

            // 2. Verify Structure Match (Are they both same nesting level?)
            // Simple check: do they encode the same generic pattern type?
            // Ideally we check depth but for now base_slot is a strong filter.

            // 3. Extract Keys from Concrete Pattern
            // We need to walk DOWN the concrete pattern to get the keys at each level
            // let mut pending_concrete = vec![concrete_pattern];
            // let mut pending_trace = vec![trace];

            // We build a single implication chain for this match:
            // "If target_hash matches concrete_hash, then ALL keys along the path must match"
            let conc_hash_bv =
                crate::symbolic::z3_ext::bv_from_u256(machine.context, *concrete_hash_u256);
            let hashes_match = target_hash._eq(&conc_hash_bv);

            let mut path_conditions = Vec::new();

            // Walk UP the chain (from outer hash to inner base)
            let mut current_trace_opt = Some(trace);
            let mut current_pattern_opt = Some(concrete_pattern);

            while let (Some(cur_trace), Some(cur_pattern)) =
                (current_trace_opt, current_pattern_opt)
            {
                // Extract Key from Trace
                if cur_trace.preimage.is_empty() {
                    break;
                }
                let sym_key = &cur_trace.preimage[0];

                // Extract Key from Concrete Pattern
                let conc_key_opt = match cur_pattern {
                    StoragePattern::FlatMapping(_, k) => *k,
                    StoragePattern::NestedMapping(_, k) => *k,
                    StoragePattern::DynamicArray(_, k) => *k,
                    _ => None,
                };

                if let Some(conc_key) = conc_key_opt {
                    let conc_key_bv =
                        crate::symbolic::z3_ext::bv_from_u256(machine.context, conc_key);
                    path_conditions.push(sym_key._eq(&conc_key_bv));
                }

                // Move to Inner Level
                match cur_pattern {
                    StoragePattern::NestedMapping(inner, _) => {
                        current_pattern_opt = Some(inner);
                        // Find trace for inner hash
                        // The inner hash is usually the SECOND element of the preimage (slot position)
                        if cur_trace.preimage.len() >= 2 {
                            let inner_hash_bv = &cur_trace.preimage[1];
                            // We must find the trace that produced this inner hash
                            current_trace_opt = machine
                                .sha3_trace
                                .iter()
                                .rev()
                                .find(|t| t.hash == *inner_hash_bv);
                        } else {
                            current_trace_opt = None;
                        }
                    }
                    _ => {
                        current_pattern_opt = None; // End of chain
                    }
                }
            }

            if !path_conditions.is_empty() {
                let all_keys_match = z3::ast::Bool::and(
                    machine.context,
                    &path_conditions.iter().collect::<Vec<_>>(),
                );
                constraints.push(hashes_match.implies(&all_keys_match));
            }
        }

        constraints
    }

    /// (Legacy) Constrain projection - kept for ref compatibility but delegates to Deep
    pub fn constrain_projection<'ctx>(
        machine: &SymbolicMachine<'ctx>,
        target_hash: &BV<'ctx>,
        trace: &SHA3Trace<'ctx>,
        pattern: &StoragePattern,
    ) -> Vec<z3::ast::Bool<'ctx>> {
        Self::constrain_deep_projection(machine, target_hash, trace, pattern)
    }
    /// Generate Forward Propagation constraints.
    /// GUIDE the solver: If `trace.hash` is UNCONSTRAINED but depends on `parent_hash`,
    /// and `parent_hash` matches a known pattern, we "Inject" the likely structure of the child.
    ///
    /// Usage: When we see `h2 = keccak(h1, key)`, and `h1` matches `balances[A]`,
    /// we propose: "If h2 is read, it likely corresponds to `balances[A][key]`".
    ///
    /// This prevents Z3 from getting stuck on `select(storage, h2)` with no idea what `h2` implies.
    pub fn constrain_forward_propagation<'ctx>(
        machine: &SymbolicMachine<'ctx>,
        trace: &SHA3Trace<'ctx>,
        pattern: &StoragePattern,
    ) -> Vec<z3::ast::Bool<'ctx>> {
        let mut constraints = Vec::new();

        // Forward propagation needs both key and parent components in the preimage.
        if trace.preimage.len() < 2 {
            return constraints;
        }

        let Some(target_base) = pattern.base_slot() else {
            return constraints;
        };
        let sym_key = &trace.preimage[0];
        let sym_parent = &trace.preimage[1];

        for (concrete_hash_u256, concrete_pattern) in &machine.detected_patterns {
            // Keep constraints local to the same structural family.
            if concrete_pattern.base_slot() != Some(target_base) {
                continue;
            }

            let shape_matches = matches!(
                (pattern, concrete_pattern),
                (
                    StoragePattern::FlatMapping(_, _),
                    StoragePattern::FlatMapping(_, _)
                ) | (
                    StoragePattern::NestedMapping(_, _),
                    StoragePattern::NestedMapping(_, _)
                ) | (
                    StoragePattern::DynamicArray(_, _),
                    StoragePattern::DynamicArray(_, _)
                )
            );
            if !shape_matches {
                continue;
            }

            let Some(concrete_key) = concrete_pattern.concrete_key() else {
                continue;
            };
            let key_match = sym_key._eq(&crate::symbolic::z3_ext::bv_from_u256(
                machine.context,
                concrete_key,
            ));

            // Parent guard:
            // - flat/dynamic mapping-like pattern: second word is concrete base slot
            // - nested mapping: second word is concrete parent hash if known
            let parent_match =
                match concrete_pattern {
                    StoragePattern::FlatMapping(base, _)
                    | StoragePattern::DynamicArray(base, _) => sym_parent._eq(
                        &crate::symbolic::z3_ext::bv_from_u256(machine.context, *base),
                    ),
                    StoragePattern::NestedMapping(inner, _) => {
                        let parent_hash = machine.detected_patterns.iter().find_map(|(h, p)| {
                            if p == inner.as_ref() {
                                Some(*h)
                            } else {
                                None
                            }
                        });
                        let Some(parent_hash) = parent_hash else {
                            continue;
                        };
                        sym_parent._eq(&crate::symbolic::z3_ext::bv_from_u256(
                            machine.context,
                            parent_hash,
                        ))
                    }
                    _ => continue,
                };

            let guard = z3::ast::Bool::and(machine.context, &[&key_match, &parent_match]);
            let hash_match = trace.hash._eq(&crate::symbolic::z3_ext::bv_from_u256(
                machine.context,
                *concrete_hash_u256,
            ));
            constraints.push(guard.implies(&hash_match));
        }

        constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::{Config, Context};

    #[test]
    fn test_detect_flat_mapping() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // key (symbolic) + slot (concrete 0)
        let key = BV::new_const(&ctx, "key", 256);
        let slot = BV::from_u64(&ctx, 0, 256);

        let trace = SHA3Trace {
            preimage: vec![key, slot],
            hash: BV::new_const(&ctx, "hash", 256),
            size: BV::from_u64(&ctx, 64, 256),
            pc: 0,
        };

        let pattern = PatternInference::infer(None, &[], &trace);

        match pattern {
            Some(StoragePattern::FlatMapping(base, _)) => {
                assert_eq!(base, U256::ZERO);
            }
            _ => panic!("Expected FlatMapping(0), got {:?}", pattern),
        }
    }

    #[test]
    fn test_detect_dynamic_array() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        // slot (concrete 5)
        let slot = BV::from_u64(&ctx, 5, 256);

        let trace = SHA3Trace {
            preimage: vec![slot],
            hash: BV::new_const(&ctx, "hash", 256),
            size: BV::from_u64(&ctx, 32, 256), // Keccak(slot) is size 32 usually? No, input is 32 bytes.
            pc: 0,
        };

        let pattern = PatternInference::infer(None, &[], &trace);
        match pattern {
            Some(StoragePattern::DynamicArray(base, _)) => {
                assert_eq!(base, U256::from(5));
            }
            _ => panic!("Expected DynamicArray(5), got {:?}", pattern),
        }
    }

    #[test]
    fn test_constrain_projection() {
        use crate::symbolic::state::SymbolicMachine;
        use z3::{Config, Context, Solver};

        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // Setup: Known concrete pattern: FlatMapping(Base=0) with Key=123
        let concrete_key_val = U256::from(123);
        let concrete_key_bv =
            crate::symbolic::z3_ext::bv_from_u256(machine.context, concrete_key_val);
        // Concrete Hash would be keccak(123 . 0). Let's simulate it with a specific value.
        let concrete_hash_val = U256::from(9999);
        let concrete_hash_bv =
            crate::symbolic::z3_ext::bv_from_u256(machine.context, concrete_hash_val);

        // Machine knows this pattern
        machine.detected_patterns.insert(
            concrete_hash_val,
            StoragePattern::FlatMapping(U256::ZERO, Some(concrete_key_val)),
        );

        // Trace: Symbolic Key, Concrete Base=0
        let sym_key = BV::new_const(&ctx, "sym_key", 256);
        let slot_zero = BV::from_u64(&ctx, 0, 256);
        let target_hash = BV::new_const(&ctx, "target_hash", 256);

        let trace = SHA3Trace {
            preimage: vec![sym_key.clone(), slot_zero],
            hash: target_hash.clone(),
            size: BV::from_u64(&ctx, 64, 256),
            pc: 0,
        };

        // We want to constrain: target_hash == concrete_hash_val
        // And see if it generates: target_hash==concrete => sym_key==123
        let pattern = StoragePattern::FlatMapping(U256::ZERO, None); // Inferred symbolic pattern

        let constraints =
            PatternInference::constrain_projection(&machine, &target_hash, &trace, &pattern);

        assert_eq!(constraints.len(), 1);

        // Verify constraint logic:
        // Assert constraint. Assert target_hash == concrete_hash. Check sym_key == 123.
        solver.assert(&constraints[0]);
        solver.assert(&target_hash._eq(&concrete_hash_bv));

        // The constraint should force sym_key == concrete_key (123)
        // Check unsat if sym_key != 123
        let check_neq = sym_key._eq(&concrete_key_bv).not();
        solver.push();
        solver.assert(&check_neq);
        assert_eq!(solver.check(), z3::SatResult::Unsat);
        solver.pop(1);
    }

    #[test]
    fn test_constrain_forward_propagation_guides_hash_from_key_and_parent() {
        use crate::symbolic::state::SymbolicMachine;
        use z3::{Config, Context, Solver};

        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        // Known concrete mapping hash: keccak(key=123, slot=0) -> 9999 (simulated concrete sample).
        let concrete_key = U256::from(123u64);
        let concrete_hash = U256::from(9999u64);
        machine.detected_patterns.insert(
            concrete_hash,
            StoragePattern::FlatMapping(U256::ZERO, Some(concrete_key)),
        );

        let sym_key = BV::new_const(&ctx, "fwd_sym_key", 256);
        let sym_parent = BV::new_const(&ctx, "fwd_sym_parent", 256);
        let target_hash = BV::new_const(&ctx, "fwd_target_hash", 256);
        let trace = SHA3Trace {
            preimage: vec![sym_key.clone(), sym_parent.clone()],
            hash: target_hash.clone(),
            size: BV::from_u64(&ctx, 64, 256),
            pc: 0,
        };

        let inferred = StoragePattern::FlatMapping(U256::ZERO, None);
        let constraints =
            PatternInference::constrain_forward_propagation(&machine, &trace, &inferred);
        assert!(!constraints.is_empty());

        // If key and parent match the concrete sample, hash must match concrete hash.
        solver.assert(&constraints[0]);
        solver.assert(&sym_key._eq(&crate::symbolic::z3_ext::bv_from_u256(&ctx, concrete_key)));
        solver.assert(&sym_parent._eq(&BV::from_u64(&ctx, 0, 256)));
        solver.assert(
            &target_hash
                ._eq(&crate::symbolic::z3_ext::bv_from_u256(&ctx, concrete_hash))
                .not(),
        );
        assert_eq!(solver.check(), z3::SatResult::Unsat);
    }
}
