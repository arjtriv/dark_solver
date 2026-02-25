use alloy::primitives::{Address, U256};
use std::collections::HashMap;
use z3::ast::{Array, Ast, BV};

use crate::symbolic::state::SymbolicMachine;
use crate::symbolic::z3_ext::u256_from_bv;

use std::fmt::Debug;

/// Strategy defining how Storage is resolved.
/// This allows swapping between "Flat Array" (Keccak-faithful) and "Algebraic Lifting" (Keccak-bypass).
pub trait StorageStrategy<'ctx>: Debug {
    /// Handle SLOAD. Returns the loaded value.
    fn sload(
        &mut self,
        machine: &SymbolicMachine<'ctx>,
        address: Address,
        slot_key: BV<'ctx>,
    ) -> BV<'ctx>;

    /// Handle SSTORE. Returns nothing (state is mutated internally).
    fn sstore(
        &mut self,
        machine: &SymbolicMachine<'ctx>,
        address: Address,
        slot_key: BV<'ctx>,
        value: BV<'ctx>,
    );

    /// Create a snapshot of the strategy state.
    fn box_clone(&self) -> Box<dyn StorageStrategy<'ctx> + 'ctx>;
}

impl<'ctx> Clone for Box<dyn StorageStrategy<'ctx> + 'ctx> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// The "Shadow State" implementation.
/// Maintains a dual representation:
/// 1. Flat Storage (via `machine.storage` - existing behavior) for compatibility.
/// 2. Algebraic Storage (Shadow Maps) for Keccak bypass.
#[derive(Debug, Clone)]
pub struct AlgebraicStorage<'ctx> {
    /// Maps (Contract Address) -> (Base Slot U256) -> (Z3 Array for this mapping)
    /// This represents `mapping(key => value)` as `Array<Key, Value>`
    /// instead of `Storage[keccak(key . slot)]`.
    pub shadow_maps: HashMap<Address, HashMap<U256, Array<'ctx>>>,
}

impl<'ctx> Default for AlgebraicStorage<'ctx> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ctx> AlgebraicStorage<'ctx> {
    pub fn new() -> Self {
        Self {
            shadow_maps: HashMap::new(),
        }
    }

    /// Helper: Identify if a slot access matches a known generic pattern
    /// Returns: (Base Slot, List of Keys in order [outer, inner, ...])
    fn resolve_pattern(
        &self,
        machine: &SymbolicMachine<'ctx>,
        slot_key: &BV<'ctx>,
    ) -> Option<(U256, Vec<BV<'ctx>>)> {
        // We assume the slot_key is the hash of the FINAL level.
        // We need to walk up the trace chain to find the Base.

        let mut keys = Vec::new();
        let mut current_hash = slot_key.clone();

        // Safety Break
        for _ in 0..10 {
            // Find trace for current hash
            // USE SEMANTIC EQUALITY "lazily" implies searching the list?
            // We use simple iteration.
            // PERF: This search is O(N) per level.
            let trace_opt = machine
                .sha3_trace
                .iter()
                .rev()
                .find(|t| t.hash._eq(&current_hash).simplify().as_bool() == Some(true));

            if let Some(trace) = trace_opt {
                // We have a trace.
                // Is this a pattern?
                // Check if we detected a pattern for this hash
                // Or infer it.

                // For nested keys, we care about the PREIMAGE.
                // Preimage: [key, parent_slot]
                if trace.preimage.len() < 2 {
                    break;
                }

                let key = trace.preimage[0].clone();
                let parent = trace.preimage[1].clone();

                // Add key to list (we are walking backwards, so this is the innermost key)
                keys.push(key);

                // Check if parent is a Concrete Base Slot (Small Int)
                if let Some(val) = u256_from_bv(&parent) {
                    if val <= U256::from(256u64) {
                        // FOUND BASE!
                        // Keys are currently [innermost, ..., outermost]
                        // Reverse to [outer, inner]
                        keys.reverse();
                        return Some((val, keys));
                    }
                }

                // Else, parent is the next hash to resolve
                current_hash = parent;
            } else {
                // No trace for this hash. Maybe it's not a Keccak-derived slot?
                break;
            }
        }

        None
    }
}

impl<'ctx> StorageStrategy<'ctx> for AlgebraicStorage<'ctx> {
    fn sload(
        &mut self,
        machine: &SymbolicMachine<'ctx>,
        address: Address,
        slot_key: BV<'ctx>,
    ) -> BV<'ctx> {
        // 1. Try to resolve pattern (Keccak Bypass)
        if let Some((base_slot, keys)) = self.resolve_pattern(machine, &slot_key) {
            // Concatenate keys to form Abstract Key
            let mut abstract_key = keys[0].clone();
            for k in &keys[1..] {
                // concat: k is appended? Or prepended?
                // mapping(a => mapping(b => v))
                // Logical key is (a, b).
                // We concat a ++ b.
                abstract_key = abstract_key.concat(k);
            }

            let default_val = crate::symbolic::utils::math::zero(machine.context);

            if let Some(base_map) = self.shadow_maps.get(&address) {
                if let Some(array) = base_map.get(&base_slot) {
                    let val = array.select(&abstract_key).as_bv().unwrap_or_else(|| {
                        // Fail-closed: unexpected array element sort mismatch.
                        crate::symbolic::utils::math::zero(machine.context)
                    });
                    return val;
                }
            }
            return default_val;
        }

        // 2. Fallback: Standard Flat Storage
        let storage_arr = machine.get_storage(address);
        storage_arr
            .select(&slot_key)
            .as_bv()
            .unwrap_or_else(|| crate::symbolic::utils::math::zero(machine.context))
    }

    fn sstore(
        &mut self,
        machine: &SymbolicMachine<'ctx>,
        address: Address,
        slot_key: BV<'ctx>,
        value: BV<'ctx>,
    ) {
        // 1. Try to resolve pattern
        if let Some((base_slot, keys)) = self.resolve_pattern(machine, &slot_key) {
            // Concatenate keys
            let mut abstract_key = keys[0].clone();
            for k in &keys[1..] {
                abstract_key = abstract_key.concat(k);
            }

            let entry = self.shadow_maps.entry(address).or_default();

            let array = entry.entry(base_slot).or_insert_with(|| {
                // Initialize with Zero
                // Domain size = key size * num keys
                let domain_size = abstract_key.get_size();
                let domain = z3::Sort::bitvector(machine.context, domain_size);
                let zero_val = crate::symbolic::utils::math::zero(machine.context);
                Array::const_array(machine.context, &domain, &zero_val)
            });

            let new_array = array.store(&abstract_key, &value);
            entry.insert(base_slot, new_array);
        }

        // If not pattern, we do nothing in Shadow State.
    }

    fn box_clone(&self) -> Box<dyn StorageStrategy<'ctx> + 'ctx> {
        Box::new(self.clone())
    }
}
