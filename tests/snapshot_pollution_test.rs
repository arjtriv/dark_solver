use alloy::primitives::{Address, U256};
use dark_solver::symbolic::patterns::{SHA3Trace, StoragePattern};
use dark_solver::symbolic::state::{
    Create2Deployment, Create2InitAudit, OracleDep, OracleType, Snapshot, SymbolicMachine,
};
use std::collections::HashMap;
use z3::ast::{Array, Ast, BV};
use z3::{Config, Context, SatResult, Solver};

fn lcg_next(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *seed
}

fn pseudo_bool(seed: &mut u64) -> bool {
    (lcg_next(seed) & 1) == 1
}

fn pseudo_bv<'ctx>(ctx: &'ctx Context, seed: &mut u64) -> BV<'ctx> {
    BV::from_u64(ctx, lcg_next(seed), 256)
}

fn pseudo_address(seed: &mut u64) -> Address {
    let mut bytes = [0u8; 20];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let chunk = lcg_next(seed).to_be_bytes();
        let n = (bytes.len() - offset).min(chunk.len());
        bytes[offset..offset + n].copy_from_slice(&chunk[..n]);
        offset += n;
    }
    Address::from_slice(&bytes)
}

fn assert_bv_eq(lhs: &BV<'_>, rhs: &BV<'_>) {
    assert_eq!(lhs._eq(rhs).simplify().as_bool(), Some(true));
}

fn assert_array_eq(lhs: &Array<'_>, rhs: &Array<'_>) {
    assert_eq!(lhs._eq(rhs).simplify().as_bool(), Some(true));
}

fn assert_bv_vec_eq(lhs: &[BV<'_>], rhs: &[BV<'_>]) {
    assert_eq!(lhs.len(), rhs.len());
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        assert_bv_eq(a, b);
    }
}

fn assert_calldata_eq(lhs: &(Array<'_>, BV<'_>), rhs: &(Array<'_>, BV<'_>)) {
    assert_array_eq(&lhs.0, &rhs.0);
    assert_bv_eq(&lhs.1, &rhs.1);
}

fn assert_bv_pair_vec_eq(lhs: &[(BV<'_>, BV<'_>)], rhs: &[(BV<'_>, BV<'_>)]) {
    assert_eq!(lhs.len(), rhs.len());
    for ((la, lb), (ra, rb)) in lhs.iter().zip(rhs.iter()) {
        assert_bv_eq(la, ra);
        assert_bv_eq(lb, rb);
    }
}

fn assert_bv_map_eq(lhs: &HashMap<BV<'_>, BV<'_>>, rhs: &HashMap<BV<'_>, BV<'_>>) {
    assert_eq!(lhs.len(), rhs.len());
    for (l_key, l_val) in lhs {
        let maybe_rhs = rhs
            .iter()
            .find(|(r_key, _)| r_key._eq(l_key).simplify().as_bool() == Some(true))
            .map(|(_, r_val)| r_val);
        let r_val = maybe_rhs.expect("missing symbolic key after restore");
        assert_bv_eq(l_val, r_val);
    }
}

fn assert_oracle_preimage_map_eq(
    lhs: &HashMap<U256, Vec<BV<'_>>>,
    rhs: &HashMap<U256, Vec<BV<'_>>>,
) {
    assert_eq!(lhs.len(), rhs.len());
    for (hash, l_terms) in lhs {
        let r_terms = rhs
            .get(hash)
            .expect("missing oracle preimage entry after restore");
        assert_bv_vec_eq(l_terms, r_terms);
    }
}

fn assert_oracle_deps_eq(lhs: &[OracleDep], rhs: &[OracleDep]) {
    assert_eq!(lhs.len(), rhs.len());
    for (l_dep, r_dep) in lhs.iter().zip(rhs.iter()) {
        assert_eq!(l_dep.source, r_dep.source);
        assert_eq!(l_dep.target, r_dep.target);
        assert_eq!(l_dep.slot, r_dep.slot);
        assert_eq!(l_dep.kind, r_dep.kind);
    }
}

fn assert_frames_eq(
    lhs: &[dark_solver::symbolic::state::CallFrame<'_>],
    rhs: &[dark_solver::symbolic::state::CallFrame<'_>],
) {
    assert_eq!(lhs.len(), rhs.len());
    for (l_frame, r_frame) in lhs.iter().zip(rhs.iter()) {
        assert_bv_vec_eq(&l_frame.stack.stack, &r_frame.stack.stack);
        assert_array_eq(&l_frame.memory, &r_frame.memory);
        assert_calldata_eq(&l_frame.calldata, &r_frame.calldata);
        assert_eq!(l_frame.pc, r_frame.pc);
        assert_eq!(l_frame.address, r_frame.address);
        assert_bv_eq(&l_frame.max_memory_offset, &r_frame.max_memory_offset);
    }
}

fn assert_manipulated_reserves_eq(
    lhs: &HashMap<Address, (BV<'_>, BV<'_>)>,
    rhs: &HashMap<Address, (BV<'_>, BV<'_>)>,
) {
    assert_eq!(lhs.len(), rhs.len());
    for (addr, (l0, l1)) in lhs {
        let (r0, r1) = rhs
            .get(addr)
            .expect("missing manipulated reserve after restore");
        assert_bv_eq(l0, r0);
        assert_bv_eq(l1, r1);
    }
}

fn assert_token_balances_eq(
    lhs: &HashMap<(Address, Address), BV<'_>>,
    rhs: &HashMap<(Address, Address), BV<'_>>,
) {
    assert_eq!(lhs.len(), rhs.len());
    for (key, l_val) in lhs {
        let r_val = rhs
            .get(key)
            .expect("missing token balance entry after restore");
        assert_bv_eq(l_val, r_val);
    }
}

fn assert_pending_keccak_chains_eq(
    lhs: &[dark_solver::symbolic::state::PendingKeccakChain<'_>],
    rhs: &[dark_solver::symbolic::state::PendingKeccakChain<'_>],
) {
    assert_eq!(lhs.len(), rhs.len());
    for (l, r) in lhs.iter().zip(rhs.iter()) {
        assert_bv_eq(&l.parent_hash, &r.parent_hash);
        assert_bv_eq(&l.child_hash, &r.child_hash);
        assert_eq!(l.parent_index, r.parent_index);
        assert_eq!(l.arity, r.arity);
        assert_eq!(l.expanded, r.expanded);
    }
}

fn assert_snapshots_identical(lhs: &Snapshot<'_>, rhs: &Snapshot<'_>) {
    assert_eq!(lhs.solver_scope_level, rhs.solver_scope_level);
    assert_eq!(lhs.storage_log_len, rhs.storage_log_len);
    assert_eq!(lhs.branch_pushes, rhs.branch_pushes);
    assert_eq!(lhs.has_called_attacker, rhs.has_called_attacker);
    assert_eq!(lhs.reentrancy_detected, rhs.reentrancy_detected);
    assert_eq!(lhs.self_destructed, rhs.self_destructed);
    assert_eq!(lhs.created_contracts_len, rhs.created_contracts_len);
    assert_eq!(lhs.create2_deployments_len, rhs.create2_deployments_len);

    assert_array_eq(&lhs.memory, &rhs.memory);
    assert_bv_vec_eq(&lhs.sym_stack.stack, &rhs.sym_stack.stack);
    assert_calldata_eq(&lhs.calldata, &rhs.calldata);
    assert_eq!(lhs.sha3_map_len, rhs.sha3_map_len);
    assert_frames_eq(&lhs.frames, &rhs.frames);
    assert_bv_map_eq(&lhs.read_cache, &rhs.read_cache);
    assert_oracle_deps_eq(&lhs.oracle_deps, &rhs.oracle_deps);
    assert_manipulated_reserves_eq(&lhs.manipulated_reserves, &rhs.manipulated_reserves);
    assert_bv_eq(&lhs.gas_remaining, &rhs.gas_remaining);
    assert_eq!(lhs.call_path, rhs.call_path);
    assert_eq!(lhs.storage_undo_len, rhs.storage_undo_len);
    assert_bv_eq(&lhs.max_memory_offset, &rhs.max_memory_offset);
    assert_bv_pair_vec_eq(&lhs.pending_calls, &rhs.pending_calls);
    assert_eq!(lhs.journal_len, rhs.journal_len);
    assert_eq!(lhs.journal_depth, rhs.journal_depth);
    assert_oracle_preimage_map_eq(&lhs.oracle_preimage_map, &rhs.oracle_preimage_map);
    assert_pending_keccak_chains_eq(&lhs.pending_keccak_chains, &rhs.pending_keccak_chains);
    assert_eq!(lhs.balance_overrides.len(), rhs.balance_overrides.len());
    for (addr, l_val) in &lhs.balance_overrides {
        let r_val = rhs
            .balance_overrides
            .get(addr)
            .expect("missing balance override after restore");
        assert_bv_eq(l_val, r_val);
    }
    assert_token_balances_eq(&lhs.token_balances, &rhs.token_balances);
    assert_eq!(lhs.visited_pcs_undo_len, rhs.visited_pcs_undo_len);

    assert_eq!(lhs.last_opcode, rhs.last_opcode);
    assert_eq!(lhs.tx_id, rhs.tx_id);
    assert_calldata_eq(&lhs.last_return_data, &rhs.last_return_data);
    assert_calldata_eq(&lhs.current_return_data, &rhs.current_return_data);
    assert_eq!(lhs.reverted, rhs.reverted);
    assert_eq!(lhs.path_constraints, rhs.path_constraints);
    assert_eq!(lhs.next_call_target, rhs.next_call_target);
    assert_eq!(lhs.max_visited_pcs, rhs.max_visited_pcs);
    assert_eq!(lhs.sha3_trace_len, rhs.sha3_trace_len);
    assert_eq!(lhs.detected_patterns, rhs.detected_patterns);
    assert_eq!(lhs.total_branches, rhs.total_branches);
    assert_eq!(lhs.reentrancy_lock, rhs.reentrancy_lock);
    assert_eq!(lhs.call_handled, rhs.call_handled);
    assert_eq!(lhs.dead_end_pcs, rhs.dead_end_pcs);

    match (&lhs.call_value, &rhs.call_value) {
        (Some(l), Some(r)) => assert_bv_eq(l, r),
        (None, None) => {}
        _ => panic!("call_value mismatch after restore"),
    }
    match (&lhs.next_call_args, &rhs.next_call_args) {
        (Some((la, lb)), Some((ra, rb))) => {
            assert_bv_eq(la, ra);
            assert_bv_eq(lb, rb);
        }
        (None, None) => {}
        _ => panic!("next_call_args mismatch after restore"),
    }

    assert_eq!(
        lhs.storage_strategy.is_some(),
        rhs.storage_strategy.is_some(),
        "storage strategy option mismatch after restore"
    );
}

#[test]
fn test_snapshot_state_pollution_fuzz() {
    for case in 0..24u64 {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        let mut machine = SymbolicMachine::new(&ctx, &solver, None);
        let mut seed = 0xC0FFEE_u64 ^ (case.wrapping_mul(0x9E3779B97F4A7C15));

        let x = BV::new_const(&ctx, format!("x_case_{case}"), 256);
        let baseline_x = pseudo_bv(&ctx, &mut seed);
        solver.push();
        machine.solver_depth += 1;
        solver.assert(&x._eq(&baseline_x));

        let attacker = pseudo_address(&mut seed);
        let target = pseudo_address(&mut seed);
        let word_offset = pseudo_bv(&ctx, &mut seed);
        let word_value = pseudo_bv(&ctx, &mut seed);
        machine.write_word(word_offset.clone(), word_value.clone());

        machine.branch_pushes = (lcg_next(&mut seed) % 8) as usize;
        machine.has_called_attacker = pseudo_bool(&mut seed);
        machine.reentrancy_detected = pseudo_bool(&mut seed);
        machine.self_destructed = pseudo_bool(&mut seed);
        machine.created_contracts.push(pseudo_bv(&ctx, &mut seed));
        machine.create2_deployments.push(Create2Deployment {
            deployer: attacker,
            salt: pseudo_bv(&ctx, &mut seed),
            init_code_hash: pseudo_bv(&ctx, &mut seed),
            predicted_address: pseudo_bv(&ctx, &mut seed),
            audit: Create2InitAudit {
                declared_len: (lcg_next(&mut seed) % 2048) as usize,
                analyzed_len: (lcg_next(&mut seed) % 2048) as usize,
                has_delegatecall: pseudo_bool(&mut seed),
                has_selfdestruct: pseudo_bool(&mut seed),
                has_nested_create2: pseudo_bool(&mut seed),
                has_callcode: pseudo_bool(&mut seed),
            },
        });
        machine
            .pending_calls
            .push((pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)));
        machine
            .read_cache
            .insert(pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed));
        machine
            .balance_overrides
            .insert(attacker, pseudo_bv(&ctx, &mut seed));
        machine
            .token_balances
            .insert((attacker, target), pseudo_bv(&ctx, &mut seed));
        machine
            .path_constraints
            .insert((lcg_next(&mut seed) % 16) as usize, pseudo_bool(&mut seed));
        machine.visited_pcs.insert(
            (lcg_next(&mut seed) % 256) as usize,
            (lcg_next(&mut seed) % 4) as usize,
        );
        machine
            .dead_end_pcs
            .insert((lcg_next(&mut seed) % 512) as usize);
        machine.call_path.push(attacker);
        machine.reentrancy_lock.insert(attacker, true);
        machine.oracle_deps.push(OracleDep {
            source: attacker,
            target,
            slot: U256::from(lcg_next(&mut seed)),
            kind: OracleType::UniV2Reserves,
        });
        machine.manipulated_reserves.insert(
            attacker,
            (pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)),
        );
        machine
            .storage_log
            .push((pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)));
        machine.sha3_map.push((
            vec![pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)],
            pseudo_bv(&ctx, &mut seed),
        ));
        machine.sha3_trace.push(SHA3Trace {
            preimage: vec![pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)],
            hash: pseudo_bv(&ctx, &mut seed),
            size: BV::from_u64(&ctx, 64, 256),
            pc: (lcg_next(&mut seed) % 1024) as usize,
        });
        machine.detected_patterns.insert(
            U256::from(lcg_next(&mut seed)),
            StoragePattern::FlatMapping(
                U256::from(lcg_next(&mut seed) % 32),
                Some(U256::from(lcg_next(&mut seed))),
            ),
        );
        machine.oracle.preimage_map.insert(
            U256::from(lcg_next(&mut seed)),
            vec![pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)],
        );
        machine.storage.insert(
            attacker,
            machine
                .get_storage(attacker)
                .store(&pseudo_bv(&ctx, &mut seed), &pseudo_bv(&ctx, &mut seed)),
        );
        machine.journal.push(vec![(
            U256::from(lcg_next(&mut seed)),
            Some(pseudo_bv(&ctx, &mut seed)),
        )]);
        machine.call_value = Some(pseudo_bv(&ctx, &mut seed));
        machine.next_call_args = Some((pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)));
        machine.next_call_target = Some((target, pseudo_bool(&mut seed)));
        machine.call_handled = pseudo_bool(&mut seed);
        machine.reverted = pseudo_bool(&mut seed);
        machine.gas_remaining = pseudo_bv(&ctx, &mut seed);
        machine.max_memory_offset = pseudo_bv(&ctx, &mut seed);
        machine.last_opcode = (lcg_next(&mut seed) & 0xff) as u8;
        machine.tx_id = (lcg_next(&mut seed) % 1000) as usize;
        machine.max_visited_pcs = (lcg_next(&mut seed) % 10_000) as usize;
        machine.total_branches = (lcg_next(&mut seed) % 500) as usize;
        machine.last_return_data.1 = pseudo_bv(&ctx, &mut seed);
        machine.current_return_data.1 = pseudo_bv(&ctx, &mut seed);

        let baseline_snapshot = machine.snapshot();

        solver.push();
        machine.solver_depth += 1;
        let branch_x = pseudo_bv(&ctx, &mut seed);
        solver.assert(&x._eq(&branch_x));

        machine.branch_pushes = machine.branch_pushes.saturating_add(7);
        machine.has_called_attacker = !machine.has_called_attacker;
        machine.reentrancy_detected = !machine.reentrancy_detected;
        machine.self_destructed = !machine.self_destructed;
        machine.created_contracts.push(pseudo_bv(&ctx, &mut seed));
        machine.create2_deployments.push(Create2Deployment {
            deployer: target,
            salt: pseudo_bv(&ctx, &mut seed),
            init_code_hash: pseudo_bv(&ctx, &mut seed),
            predicted_address: pseudo_bv(&ctx, &mut seed),
            audit: Create2InitAudit {
                declared_len: (lcg_next(&mut seed) % 2048) as usize,
                analyzed_len: (lcg_next(&mut seed) % 2048) as usize,
                has_delegatecall: pseudo_bool(&mut seed),
                has_selfdestruct: pseudo_bool(&mut seed),
                has_nested_create2: pseudo_bool(&mut seed),
                has_callcode: pseudo_bool(&mut seed),
            },
        });
        machine.pending_calls.clear();
        machine.read_cache.clear();
        machine.balance_overrides.clear();
        machine.token_balances.clear();
        machine.path_constraints.clear();
        machine.visited_pcs.clear();
        machine.dead_end_pcs.clear();
        machine.call_path.clear();
        machine.reentrancy_lock.clear();
        machine.oracle_deps.clear();
        machine.manipulated_reserves.clear();
        machine
            .storage_log
            .push((pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)));
        machine.sha3_map.push((
            vec![pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)],
            pseudo_bv(&ctx, &mut seed),
        ));
        machine.sha3_trace.push(SHA3Trace {
            preimage: vec![pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed)],
            hash: pseudo_bv(&ctx, &mut seed),
            size: BV::from_u64(&ctx, 64, 256),
            pc: (lcg_next(&mut seed) % 1024) as usize,
        });
        machine.detected_patterns.clear();
        machine.oracle.preimage_map.clear();
        machine.storage.clear();
        machine.journal.push(vec![(
            U256::from(lcg_next(&mut seed)),
            Some(pseudo_bv(&ctx, &mut seed)),
        )]);
        machine.call_value = None;
        machine.next_call_args = None;
        machine.next_call_target = None;
        machine.call_handled = !machine.call_handled;
        machine.reverted = !machine.reverted;
        machine.gas_remaining = pseudo_bv(&ctx, &mut seed);
        machine.max_memory_offset = pseudo_bv(&ctx, &mut seed);
        machine.last_opcode = machine.last_opcode.wrapping_add(1);
        machine.tx_id = machine.tx_id.saturating_add(1);
        machine.max_visited_pcs = machine.max_visited_pcs.saturating_add(1);
        machine.total_branches = machine.total_branches.saturating_add(1);
        machine.storage_strategy = None;
        machine.write_word(pseudo_bv(&ctx, &mut seed), pseudo_bv(&ctx, &mut seed));

        machine.restore(&baseline_snapshot);
        let restored_snapshot = machine.snapshot();
        assert_snapshots_identical(&baseline_snapshot, &restored_snapshot);

        solver.push();
        solver.assert(&x._eq(&baseline_x));
        assert_eq!(solver.check(), SatResult::Sat);
        solver.pop(1);
    }
}
