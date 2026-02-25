#[cfg(test)]
mod tests {
    use crate::symbolic::oracle::KeccakOracle;
    use alloy::primitives::{address, keccak256, Address, U256};
    use z3::ast::BV;

    #[test]
    fn test_nested_mapping_precomputation() {
        let mut oracle = KeccakOracle::new();
        let attacker = address!("0000000000000000000000000000000000001337");
        let target = address!("000000000000000000000000000000000000beef");

        oracle.precompute_common_slots(attacker, Some(target));

        // 1. Verify basic balance slot (slot 0)
        let mut input1 = vec![0u8; 12];
        input1.extend_from_slice(attacker.as_slice());
        input1.extend_from_slice(&U256::from(0).to_be_bytes::<32>());
        let hash1 = U256::from_be_bytes(keccak256(&input1).0);

        let info1 = oracle
            .resolve_slot(hash1)
            .expect("Failed to resolve balance slot");
        assert!(info1.description.contains("balances[attacker]"));

        // 2. Verify target balance slot
        let mut input_t = vec![0u8; 12];
        input_t.extend_from_slice(target.as_slice());
        input_t.extend_from_slice(&U256::from(0).to_be_bytes::<32>());
        let hash_t = U256::from_be_bytes(keccak256(&input_t).0);
        let info_t = oracle
            .resolve_slot(hash_t)
            .expect("Failed to resolve target balance slot");
        assert!(info_t.description.contains("balances[target]"));

        // 3. Verify nested allowance slot (Attacker is OWNER)
        // spender = Address::ZERO, owner = attacker, slot = 1
        let mut inner_input = vec![0u8; 12];
        inner_input.extend_from_slice(attacker.as_slice());
        inner_input.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let inner_hash = keccak256(&inner_input);

        let mut outer_input = vec![0u8; 12];
        outer_input.extend_from_slice(Address::ZERO.as_slice());
        outer_input.extend_from_slice(&inner_hash.0);
        let outer_hash = U256::from_be_bytes(keccak256(&outer_input).0);

        let info2 = oracle
            .resolve_slot(outer_hash)
            .expect("Failed to resolve nested allowance slot (OWNER)");
        assert!(info2.description.contains("allowance[attacker]"));

        // 4. Verify nested allowance slot (Attacker is SPENDER)
        // owner = target, spender = attacker, slot = 1
        let mut inner_input_s = vec![0u8; 12];
        inner_input_s.extend_from_slice(target.as_slice());
        inner_input_s.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let inner_hash_s = keccak256(&inner_input_s);

        let mut outer_input_s = vec![0u8; 12];
        outer_input_s.extend_from_slice(attacker.as_slice());
        outer_input_s.extend_from_slice(&inner_hash_s.0);
        let outer_hash_s = U256::from_be_bytes(keccak256(&outer_input_s).0);

        let info_s = oracle
            .resolve_slot(outer_hash_s)
            .expect("Failed to resolve nested allowance slot (SPENDER)");
        assert!(info_s.description.contains("allowance[target][attacker]"));
    }

    #[test]
    fn test_memory_cache_invalidation() {
        use crate::symbolic::state::SymbolicMachine;
        use z3::{Config, Context, Solver};

        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        let offset = BV::from_u64(&ctx, 0x100, 256);
        let val1 = BV::from_u64(&ctx, 0x42, 256);
        let val2 = BV::from_u64(&ctx, 0x1337, 256);

        // 1. Write word and read it (should be cached)
        machine.write_word(offset.clone(), val1.clone());
        let _read1 = machine.read_word(offset.clone());
        assert_eq!(machine.read_cache.len(), 1);

        // 2. Write another word (should clear cache)
        machine.write_word(BV::from_u64(&ctx, 0x200, 256), val2.clone());
        assert_eq!(machine.read_cache.len(), 0);

        // 3. Read again (should re-cache)
        let _ = machine.read_word(offset.clone());
        assert_eq!(machine.read_cache.len(), 1);

        // 4. Write byte (should clear cache)
        machine.write_byte(
            BV::from_u64(&ctx, 0x100, 256),
            BV::from_u64(&ctx, 0xff, 256),
        );
        assert_eq!(machine.read_cache.len(), 0);
    }

    #[test]
    fn test_oracle_dependency_discovery() {
        use crate::symbolic::state::{OracleType, SymbolicMachine};
        use z3::{Config, Context, Solver};

        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);

        let pair = address!("0000000000000000000000000000000000000001");

        // getReserves() selector logic check
        // In actual code, record_oracle_dependency is called with specific args, not selector.
        // We simulate the CALL logic invoking it:
        machine.record_oracle_dependency(pair, U256::from(0), OracleType::UniV2Reserves);

        assert_eq!(machine.oracle_deps.len(), 1);
        assert_eq!(machine.oracle_deps[0].target, pair); // source field is unused/dummy usually
        assert_eq!(machine.oracle_deps[0].kind, OracleType::UniV2Reserves);

        // Duplicate check (should NOT deduplicate by default in current impl, checking behavior)
        machine.record_oracle_dependency(pair, U256::from(0), OracleType::UniV2Reserves);
        assert_eq!(machine.oracle_deps.len(), 2);

        // Chainlink latestAnswer()
        machine.record_oracle_dependency(pair, U256::from(0), OracleType::ChainlinkFeed);
        assert_eq!(machine.oracle_deps.len(), 3);
        assert_eq!(machine.oracle_deps[2].kind, OracleType::ChainlinkFeed);
    }
}
