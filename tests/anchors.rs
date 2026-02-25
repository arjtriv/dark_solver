mod anchor_utils;

#[path = "anchors/phantom_profit.rs"]
pub mod phantom_profit;

#[path = "anchors/delegatecall_spoof.rs"]
pub mod delegatecall_spoof;

#[path = "anchors/k_overflow.rs"]
pub mod k_overflow;

#[path = "anchors/state_pollution.rs"]
pub mod state_pollution;

#[path = "anchors/manip_overflow.rs"]
pub mod manip_overflow;

#[path = "anchors/reserve_overflow.rs"]
pub mod reserve_overflow;

#[path = "anchors/phantom_liquidity.rs"]
pub mod phantom_liquidity;

#[path = "anchors/uniswap_v3.rs"]
pub mod uniswap_v3;

#[path = "anchors/uniswap_v3_bitmap.rs"]
pub mod uniswap_v3_bitmap;

#[path = "anchors/curve_lending.rs"]
pub mod curve_lending;

#[path = "anchors/lending_modes.rs"]
pub mod lending_modes;

#[path = "anchors/lending_overflow.rs"]
pub mod lending_overflow;

#[path = "anchors/oracle_spot_probe.rs"]
pub mod oracle_spot_probe;

#[path = "anchors/panic_propagation.rs"]
pub mod panic_propagation;

#[path = "anchors/shadow_verifier.rs"]
pub mod shadow_verifier;

#[path = "anchors/uniswap_v4_hooks.rs"]
pub mod uniswap_v4_hooks;

#[path = "anchors/uniswap_v4_pool_manager.rs"]
pub mod uniswap_v4_pool_manager;

#[path = "anchors/curve_stableswap_math.rs"]
pub mod curve_stableswap_math;

#[path = "anchors/balancer_weighted_math.rs"]
pub mod balancer_weighted_math;

#[path = "anchors/slippage_solve_phase_gate.rs"]
pub mod slippage_solve_phase_gate;

#[path = "anchors/erc4626_invariant.rs"]
pub mod erc4626_invariant;

#[path = "anchors/multi_block_gas_test.rs"]
pub mod multi_block_gas_test;

#[path = "anchors/pattern_u256_key.rs"]
pub mod pattern_u256_key;

#[path = "anchors/parallel_bench.rs"]
pub mod parallel_bench;

#[path = "anchors/division_by_zero.rs"]
pub mod division_by_zero;

#[path = "anchors/create2_predictive_audit.rs"]
pub mod create2_predictive_audit;

#[path = "anchors/reentrancy_invariant_targeting.rs"]
pub mod reentrancy_invariant_targeting;

#[path = "anchors/keccak_lazy_chain.rs"]
pub mod keccak_lazy_chain;

#[path = "anchors/keccak_preimage_memoization.rs"]
pub mod keccak_preimage_memoization;

#[path = "anchors/telemetry_dashboard.rs"]
pub mod telemetry_dashboard;

#[path = "anchors/headless_jsonl_telemetry_v2.rs"]
pub mod headless_jsonl_telemetry_v2;

#[path = "anchors/targeted_l2_opcode_soundness.rs"]
pub mod targeted_l2_opcode_soundness;

#[path = "anchors/localized_context_expansion.rs"]
pub mod localized_context_expansion;

#[path = "anchors/compact_binary_logs.rs"]
pub mod compact_binary_logs;

#[path = "anchors/audit_only_executor_submission_mode_gate.rs"]
pub mod audit_only_executor_submission_mode_gate;

#[path = "anchors/config_url_validation.rs"]
pub mod config_url_validation;

#[path = "anchors/gauntlet_top100.rs"]
pub mod gauntlet_top100;

#[path = "anchors/access_list_generation.rs"]
pub mod access_list_generation;

#[path = "anchors/simhash_fuzzy_contract_classification.rs"]
pub mod simhash_fuzzy_contract_classification;

#[path = "anchors/predictive_mempool_hydration.rs"]
pub mod predictive_mempool_hydration;

#[path = "anchors/forkdb_getproof_support_latch.rs"]
pub mod forkdb_getproof_support_latch;

#[path = "anchors/forkdb_getproof_key_encoding.rs"]
pub mod forkdb_getproof_key_encoding;

#[path = "anchors/forkdb_slot_discovery_no_deep_copy.rs"]
pub mod forkdb_slot_discovery_no_deep_copy;

#[path = "anchors/log_light_dedupe_o1.rs"]
pub mod log_light_dedupe_o1;

#[path = "anchors/soundness_feedback.rs"]
pub mod soundness_feedback;

#[path = "anchors/bundle_obfuscation.rs"]
pub mod bundle_obfuscation;

#[path = "anchors/private_rpc_handshake.rs"]
pub mod private_rpc_handshake;

#[path = "anchors/fail_closed_submission_guards.rs"]
pub mod fail_closed_submission_guards;

#[path = "anchors/scanner_forkdb_fail_closed_guards.rs"]
pub mod scanner_forkdb_fail_closed_guards;

#[path = "anchors/builder_routing_hotpath_cache.rs"]
pub mod builder_routing_hotpath_cache;

#[path = "anchors/scanner_token_valuation_guards.rs"]
pub mod scanner_token_valuation_guards;

#[path = "anchors/scanner_priority_token_priceability.rs"]
pub mod scanner_priority_token_priceability;

#[path = "anchors/scanner_top_priority_token_cache.rs"]
pub mod scanner_top_priority_token_cache;

#[path = "anchors/scanner_compact_error_single_pass.rs"]
pub mod scanner_compact_error_single_pass;

#[path = "anchors/scanner_forkdb_incremental_hardening.rs"]
pub mod scanner_forkdb_incremental_hardening;

#[path = "anchors/scanner_fast_filter_gate.rs"]
pub mod scanner_fast_filter_gate;

#[path = "anchors/forkdb_storage_cache.rs"]
pub mod forkdb_storage_cache;

#[path = "anchors/scanner_dust_sweeper_budget.rs"]
pub mod scanner_dust_sweeper_budget;

#[path = "anchors/scanner_dust_candidate_set_cap.rs"]
pub mod scanner_dust_candidate_set_cap;

#[path = "anchors/scanner_skip_hotpath_sorting.rs"]
pub mod scanner_skip_hotpath_sorting;

#[path = "anchors/executor_failed_step_guard.rs"]
pub mod executor_failed_step_guard;

#[path = "anchors/scanner_high_value_uncertainty_budget.rs"]
pub mod scanner_high_value_uncertainty_budget;

#[path = "anchors/scanner_high_value_cache_signal_separation.rs"]
pub mod scanner_high_value_cache_signal_separation;

#[path = "anchors/scanner_balance_of_calldata_stack_buffer.rs"]
pub mod scanner_balance_of_calldata_stack_buffer;

#[path = "anchors/scanner_block_worker_spawn_backpressure.rs"]
pub mod scanner_block_worker_spawn_backpressure;

#[path = "anchors/scanner_hash_mode_block_budget.rs"]
pub mod scanner_hash_mode_block_budget;

#[path = "anchors/scanner_receipt_fallback_pressure_gate.rs"]
pub mod scanner_receipt_fallback_pressure_gate;

#[path = "anchors/scanner_full_block_ingest_parallel.rs"]
pub mod scanner_full_block_ingest_parallel;

#[path = "anchors/scanner_full_block_log_enrichment.rs"]
pub mod scanner_full_block_log_enrichment;

#[path = "anchors/scanner_full_block_deferred_tvl_probes.rs"]
pub mod scanner_full_block_deferred_tvl_probes;

#[path = "anchors/scanner_capital_profiler_decode_fallback.rs"]
pub mod scanner_capital_profiler_decode_fallback;

#[path = "anchors/scanner_capital_profiler_block_timebox.rs"]
pub mod scanner_capital_profiler_block_timebox;

#[path = "anchors/scanner_sequencer_ingestion_backpressure.rs"]
pub mod scanner_sequencer_ingestion_backpressure;

#[path = "anchors/scanner_capital_profiler_adaptive_chunking.rs"]
pub mod scanner_capital_profiler_adaptive_chunking;

#[path = "anchors/scanner_fallback_semaphore_lanes.rs"]
pub mod scanner_fallback_semaphore_lanes;

#[path = "anchors/scanner_packed_path_address_extraction.rs"]
pub mod scanner_packed_path_address_extraction;

#[path = "anchors/scanner_backfill_high_value_gate.rs"]
pub mod scanner_backfill_high_value_gate;

#[path = "anchors/scanner_backfill_global_cooldown_gate.rs"]
pub mod scanner_backfill_global_cooldown_gate;

#[path = "anchors/scanner_pending_candidate_linear_dedupe.rs"]
pub mod scanner_pending_candidate_linear_dedupe;

#[path = "anchors/scanner_capital_profiler_token_cache.rs"]
pub mod scanner_capital_profiler_token_cache;

#[path = "anchors/forkdb_debug_storage_pool_resilience.rs"]
pub mod forkdb_debug_storage_pool_resilience;

#[path = "anchors/forkdb_debug_method_latch_isolation.rs"]
pub mod forkdb_debug_method_latch_isolation;

#[path = "anchors/executor_gas_solver_cache.rs"]
pub mod executor_gas_solver_cache;

#[path = "anchors/executor_deterministic_builder_ranking.rs"]
pub mod executor_deterministic_builder_ranking;

#[path = "anchors/executor_builder_ranking_cached_fallback.rs"]
pub mod executor_builder_ranking_cached_fallback;

#[path = "anchors/executor_signing_hex_encode_boundary.rs"]
pub mod executor_signing_hex_encode_boundary;

#[path = "anchors/executor_forkdb_scanner_hotpath_hardening.rs"]
pub mod executor_forkdb_scanner_hotpath_hardening;

#[path = "anchors/scanner_executor_ingest_probe_budget.rs"]
pub mod scanner_executor_ingest_probe_budget;

#[path = "anchors/scanner_public_ws_race.rs"]
pub mod scanner_public_ws_race;

#[path = "anchors/generalized_frontrun_mirror.rs"]
pub mod generalized_frontrun_mirror;

#[path = "anchors/payload_polymorphism.rs"]
pub mod payload_polymorphism;

#[path = "anchors/momentum_gas_oracle.rs"]
pub mod momentum_gas_oracle;

#[path = "anchors/sender_block_pinning.rs"]
pub mod sender_block_pinning;

#[path = "anchors/init_race.rs"]
pub mod init_race;

#[path = "anchors/fee_on_transfer.rs"]
pub mod fee_on_transfer;

#[path = "anchors/dust_sweeper.rs"]
pub mod dust_sweeper;

#[path = "anchors/batch_capital_profiler.rs"]
pub mod batch_capital_profiler;

#[path = "anchors/priority_hot_lane_ingestion.rs"]
pub mod priority_hot_lane_ingestion;

#[path = "anchors/distributed_state_hydration.rs"]
pub mod distributed_state_hydration;

#[path = "anchors/atomic_invariant_anchors.rs"]
pub mod atomic_invariant_anchors;

#[path = "anchors/flash_swap_providers.rs"]
pub mod flash_swap_providers;

#[path = "anchors/self_heal_solver.rs"]
pub mod self_heal_solver;

#[path = "anchors/solver_runner_join_fail_closed.rs"]
pub mod solver_runner_join_fail_closed;

#[path = "anchors/setup_dependency_storage_scan_fail_closed.rs"]
pub mod setup_dependency_storage_scan_fail_closed;

#[path = "anchors/setup_chain_id_no_hardcode.rs"]
pub mod setup_chain_id_no_hardcode;

#[path = "anchors/symbolic_chain_id_fail_closed.rs"]
pub mod symbolic_chain_id_fail_closed;

#[path = "anchors/verifier_panic_decode_no_zero_default.rs"]
pub mod verifier_panic_decode_no_zero_default;

#[path = "anchors/triple_invariant_gate.rs"]
pub mod triple_invariant_gate;

#[path = "anchors/bit_level_soundness.rs"]
pub mod bit_level_soundness;

#[path = "anchors/triple_invariant_protocol_audit.rs"]
pub mod triple_invariant_protocol_audit;

#[path = "anchors/no_silent_failure_error_lifting.rs"]
pub mod no_silent_failure_error_lifting;

#[path = "anchors/as_u64_silent_failure_audit.rs"]
pub mod as_u64_silent_failure_audit;

#[path = "anchors/z3_bv_conversion_reliability.rs"]
pub mod z3_bv_conversion_reliability;

#[path = "anchors/verified_zero_hydration.rs"]
pub mod verified_zero_hydration;

#[path = "anchors/accrued_interest_modeling.rs"]
pub mod accrued_interest_modeling;

#[path = "anchors/recursive_proxy_resolver.rs"]
pub mod recursive_proxy_resolver;

#[path = "anchors/multicall3_batch_discovery.rs"]
pub mod multicall3_batch_discovery;

#[path = "anchors/cross_contract_linkage_discovery.rs"]
pub mod cross_contract_linkage_discovery;

#[path = "anchors/multi_tick_uniswap_v3_modeling.rs"]
pub mod multi_tick_uniswap_v3_modeling;

#[path = "anchors/latency_aware_hydra_routing.rs"]
pub mod latency_aware_hydra_routing;

#[path = "anchors/macro_based_snapshotting.rs"]
pub mod macro_based_snapshotting;

#[path = "anchors/generational_state_indices.rs"]
pub mod generational_state_indices;

#[path = "anchors/high_fidelity_l1_gas_modeling.rs"]
pub mod high_fidelity_l1_gas_modeling;

#[path = "anchors/local_first_replay_gate.rs"]
pub mod local_first_replay_gate;

#[path = "anchors/zero_leak_memory_profile.rs"]
pub mod zero_leak_memory_profile;

#[path = "anchors/block_interval_solve_rate.rs"]
pub mod block_interval_solve_rate;

#[path = "anchors/helper_location_standard.rs"]
pub mod helper_location_standard;

#[path = "anchors/native_sqlite_driver.rs"]
pub mod native_sqlite_driver;

#[path = "anchors/high_fidelity_storage_crawler.rs"]
pub mod high_fidelity_storage_crawler;

#[path = "anchors/opstack_decoder_hardening.rs"]
pub mod opstack_decoder_hardening;

#[path = "anchors/opstack_l1_basefee_block_cache.rs"]
pub mod opstack_l1_basefee_block_cache;

#[path = "anchors/intelligent_rate_limit_backoff.rs"]
pub mod intelligent_rate_limit_backoff;

#[path = "anchors/continuous_backfill_mode.rs"]
pub mod continuous_backfill_mode;

#[path = "anchors/metamorphic_lifecycle.rs"]
pub mod metamorphic_lifecycle;

#[path = "anchors/symbolic_precompiles.rs"]
pub mod symbolic_precompiles;

#[path = "anchors/delegatecall_storage_clash.rs"]
pub mod delegatecall_storage_clash;

#[path = "anchors/msg_value_loop_persistence.rs"]
pub mod msg_value_loop_persistence;

#[path = "anchors/dirty_address_bits.rs"]
pub mod dirty_address_bits;

#[path = "anchors/symbolic_fuzzing.rs"]
pub mod symbolic_fuzzing;

#[path = "anchors/differential_constraint_analysis.rs"]
pub mod differential_constraint_analysis;

#[path = "anchors/state_transition_cycle.rs"]
pub mod state_transition_cycle;

#[path = "anchors/taint_flow_storage.rs"]
pub mod taint_flow_storage;

#[path = "anchors/polynomial_invariant_solver.rs"]
pub mod polynomial_invariant_solver;

#[path = "anchors/psm_draining.rs"]
pub mod psm_draining;

#[path = "anchors/liquidation_spiral.rs"]
pub mod liquidation_spiral;

#[path = "anchors/twap_oracle_manipulation.rs"]
pub mod twap_oracle_manipulation;

#[path = "anchors/interest_rate_model_gaming.rs"]
pub mod interest_rate_model_gaming;

#[path = "anchors/collateral_factor_ltv_lag.rs"]
pub mod collateral_factor_ltv_lag;

#[path = "anchors/redemption_arbitrage.rs"]
pub mod redemption_arbitrage;

#[path = "anchors/dust_bad_debt_creation.rs"]
pub mod dust_bad_debt_creation;

#[path = "anchors/amm_price_impact.rs"]
pub mod amm_price_impact;

#[path = "anchors/weak_prng.rs"]
pub mod weak_prng;

#[path = "anchors/commit_reveal_bypass.rs"]
pub mod commit_reveal_bypass;

#[path = "anchors/gambling_contract_scanner.rs"]
pub mod gambling_contract_scanner;

#[path = "anchors/chainlink_vrf_timing_attack.rs"]
pub mod chainlink_vrf_timing_attack;

#[path = "anchors/governance_flash_loan_voting.rs"]
pub mod governance_flash_loan_voting;

#[path = "anchors/payload_hardening.rs"]
pub mod payload_hardening;

#[path = "anchors/direct_stream_builder_fanout.rs"]
pub mod direct_stream_builder_fanout;

#[path = "anchors/stealth_vault.rs"]
pub mod stealth_vault;

#[path = "anchors/log_light_detection.rs"]
pub mod log_light_detection;

#[path = "anchors/distributed_hydra_ingestion.rs"]
pub mod distributed_hydra_ingestion;

#[path = "anchors/pinned_block_fork_replay.rs"]
pub mod pinned_block_fork_replay;

#[path = "anchors/multicall3_batch_hydration.rs"]
pub mod multicall3_batch_hydration;

#[path = "anchors/concrete_fuzz_fast_lane.rs"]
pub mod concrete_fuzz_fast_lane;

#[path = "anchors/ev_based_job_pruning.rs"]
pub mod ev_based_job_pruning;

#[path = "anchors/atomic_payload_bundling.rs"]
pub mod atomic_payload_bundling;

#[path = "anchors/timelock_expiry_sniping.rs"]
pub mod timelock_expiry_sniping;

#[path = "anchors/quorum_manipulation.rs"]
pub mod quorum_manipulation;

#[path = "anchors/delegatee_hijack.rs"]
pub mod delegatee_hijack;

#[path = "anchors/erc721_callback_reentrancy.rs"]
pub mod erc721_callback_reentrancy;

#[path = "anchors/erc1155_callback_reentrancy.rs"]
pub mod erc1155_callback_reentrancy;

#[path = "anchors/erc721_mint_callback_drain.rs"]
pub mod erc721_mint_callback_drain;

#[path = "anchors/erc721_approval_hijack.rs"]
pub mod erc721_approval_hijack;

#[path = "anchors/read_only_reentrancy.rs"]
pub mod read_only_reentrancy;

#[path = "anchors/read_only_reentrancy_scanner.rs"]
pub mod read_only_reentrancy_scanner;

#[path = "anchors/vault_inflation.rs"]
pub mod vault_inflation;

#[path = "anchors/share_rounding_griefing.rs"]
pub mod share_rounding_griefing;

#[path = "anchors/golden_ratio_restructure.rs"]
pub mod golden_ratio_restructure;

#[path = "anchors/dark_error_hierarchy.rs"]
pub mod dark_error_hierarchy;

#[path = "anchors/global_proptest_gauntlet.rs"]
pub mod global_proptest_gauntlet;

#[path = "anchors/unified_target_hydration.rs"]
pub mod unified_target_hydration;

#[path = "anchors/preemptive_bytecode_slicing.rs"]
pub mod preemptive_bytecode_slicing;

#[path = "anchors/fast_path_revert_injection.rs"]
pub mod fast_path_revert_injection;

#[path = "anchors/block_liveness_gate.rs"]
pub mod block_liveness_gate;

#[path = "anchors/z3_context_bootstrap_optimization.rs"]
pub mod z3_context_bootstrap_optimization;

#[path = "anchors/deep_sat_persistence.rs"]
pub mod deep_sat_persistence;

#[path = "anchors/background_solver_queue.rs"]
pub mod background_solver_queue;

#[path = "anchors/abstract_state_independent_proofs.rs"]
pub mod abstract_state_independent_proofs;

#[path = "anchors/jit_tuner.rs"]
pub mod jit_tuner;

#[path = "anchors/differential_state_migration.rs"]
pub mod differential_state_migration;

#[path = "anchors/pressure_optimized_risk_weighting.rs"]
pub mod pressure_optimized_risk_weighting;

#[path = "anchors/l1_gas_price_integration.rs"]
pub mod l1_gas_price_integration;

#[path = "anchors/gas_solver_word_parse_overflow_guard.rs"]
pub mod gas_solver_word_parse_overflow_guard;

#[path = "anchors/sequencer_ws_ingestion.rs"]
pub mod sequencer_ws_ingestion;

#[path = "anchors/proof_persistence_engine.rs"]
pub mod proof_persistence_engine;

#[path = "anchors/eip_197_pairing_symbolic_model.rs"]
pub mod eip_197_pairing_symbolic_model;

#[path = "anchors/eip_196_scalar_multi_add.rs"]
pub mod eip_196_scalar_multi_add;

#[path = "anchors/groth16_verifier_audit.rs"]
pub mod groth16_verifier_audit;

#[path = "anchors/precompile_soundness_eip198.rs"]
pub mod precompile_soundness_eip198;

#[path = "anchors/l2_native_bridge_arbitrage.rs"]
pub mod l2_native_bridge_arbitrage;

#[path = "anchors/priority_sequence_indexer.rs"]
pub mod priority_sequence_indexer;

#[path = "anchors/multi_sender_logic.rs"]
pub mod multi_sender_logic;

#[path = "anchors/deep_sniper_force_solve.rs"]
pub mod deep_sniper_force_solve;

#[path = "anchors/deep_sniper_chain_id_autodetect.rs"]
pub mod deep_sniper_chain_id_autodetect;

#[path = "anchors/rpc_global_cooldown.rs"]
pub mod rpc_global_cooldown;

#[path = "anchors/rpc_now_ms_monotonic_nonzero.rs"]
pub mod rpc_now_ms_monotonic_nonzero;

#[path = "anchors/runtime_now_ms_monotonic_nonzero.rs"]
pub mod runtime_now_ms_monotonic_nonzero;

#[path = "anchors/auxiliary_now_ms_monotonic_nonzero.rs"]
pub mod auxiliary_now_ms_monotonic_nonzero;

#[path = "anchors/extended_now_ms_monotonic_nonzero.rs"]
pub mod extended_now_ms_monotonic_nonzero;

#[path = "anchors/flight_controller_scanner_status.rs"]
pub mod flight_controller_scanner_status;

#[path = "anchors/flight_controller_now_ms_monotonic_nonzero.rs"]
pub mod flight_controller_now_ms_monotonic_nonzero;

#[path = "anchors/manual_target_done_override.rs"]
pub mod manual_target_done_override;

#[path = "anchors/ws_gap_recovery_reconciliation.rs"]
pub mod ws_gap_recovery_reconciliation;

#[path = "anchors/unknown_opstack_tx_type_survival.rs"]
pub mod unknown_opstack_tx_type_survival;

#[path = "anchors/inclusion_outcome_attribution.rs"]
pub mod inclusion_outcome_attribution;

#[path = "anchors/builder_reliability_routing.rs"]
pub mod builder_reliability_routing;

#[path = "anchors/replay_freshness_sla.rs"]
pub mod replay_freshness_sla;

#[path = "anchors/realized_expected_drift_governor.rs"]
pub mod realized_expected_drift_governor;

#[path = "anchors/profitability_calibration_harness.rs"]
pub mod profitability_calibration_harness;

#[path = "anchors/contested_inclusion_benchmark_harness.rs"]
pub mod contested_inclusion_benchmark_harness;

#[path = "anchors/contested_bench_dedup.rs"]
pub mod contested_bench_dedup;

#[path = "anchors/deterministic_submission_ledger.rs"]
pub mod deterministic_submission_ledger;

#[path = "anchors/calibration_dedup.rs"]
pub mod calibration_dedup;

#[path = "anchors/runtime_safety_rails_fail_closed.rs"]
pub mod runtime_safety_rails_fail_closed;

#[path = "anchors/profit_weighted_execution_policy.rs"]
pub mod profit_weighted_execution_policy;

#[path = "anchors/global_fail_closed_policy.rs"]
pub mod global_fail_closed_policy;

#[path = "anchors/cow_based_snapshotting.rs"]
pub mod cow_based_snapshotting;

#[path = "anchors/price_confidence_coverage_gate.rs"]
pub mod price_confidence_coverage_gate;

#[path = "anchors/modular_tactics_registry.rs"]
pub mod modular_tactics_registry;

#[path = "anchors/flash_loan_provider_registry.rs"]
pub mod flash_loan_provider_registry;

#[path = "anchors/atomic_exit_dumper.rs"]
pub mod atomic_exit_dumper;

#[path = "anchors/mempool_mirror_target_gating.rs"]
pub mod mempool_mirror_target_gating;

#[path = "anchors/coinbase_bribe_direct.rs"]
pub mod coinbase_bribe_direct;

#[path = "anchors/flash_loan_registry_dynamic_specs.rs"]
pub mod flash_loan_registry_dynamic_specs;

#[path = "anchors/tvl_weighted_target_acquisition.rs"]
pub mod tvl_weighted_target_acquisition;

#[path = "anchors/deep_invariant_analysis_10hop.rs"]
pub mod deep_invariant_analysis_10hop;

#[path = "anchors/watch_cache_trap.rs"]
pub mod watch_cache_trap;

#[path = "anchors/private_rpc_hint_sniper.rs"]
pub mod private_rpc_hint_sniper;

#[path = "anchors/tip_auto_scaler.rs"]
pub mod tip_auto_scaler;

#[path = "anchors/immediate_bundle_relay.rs"]
pub mod immediate_bundle_relay;

#[path = "anchors/conditional_bundle_execution.rs"]
pub mod conditional_bundle_execution;

#[path = "anchors/executor_conditional_storage_prefetch.rs"]
pub mod executor_conditional_storage_prefetch;

#[path = "anchors/executor_conditional_predicate_dedupe.rs"]
pub mod executor_conditional_predicate_dedupe;

#[path = "anchors/executor_hotpath_stdio_gate.rs"]
pub mod executor_hotpath_stdio_gate;

#[path = "anchors/http_client_builder_panic_hardening.rs"]
pub mod http_client_builder_panic_hardening;

#[path = "anchors/honeypot_logic_sieve.rs"]
pub mod honeypot_logic_sieve;

#[path = "anchors/gas_griefing_protection.rs"]
pub mod gas_griefing_protection;

#[path = "anchors/hermetic_proof_cache.rs"]
pub mod hermetic_proof_cache;

#[path = "anchors/proxy_blindness.rs"]
pub mod proxy_blindness;

#[path = "anchors/solver_state_cache_event_driven.rs"]
pub mod solver_state_cache_event_driven;

#[path = "anchors/generalized_frontrun_smart_mirror.rs"]
pub mod generalized_frontrun_smart_mirror;

#[path = "anchors/setup_deep_scan_preloader.rs"]
pub mod setup_deep_scan_preloader;

#[path = "anchors/main_daily_stop_loss.rs"]
pub mod main_daily_stop_loss;

#[path = "anchors/slippage_oracle_quoter.rs"]
pub mod slippage_oracle_quoter;

#[path = "anchors/slippage_oracle_decode_fail_closed.rs"]
pub mod slippage_oracle_decode_fail_closed;

#[path = "anchors/ops_async_alert_telemetry.rs"]
pub mod ops_async_alert_telemetry;

#[path = "anchors/ops_blackbox_flight_recorder.rs"]
pub mod ops_blackbox_flight_recorder;

#[path = "anchors/callbundle_preflight_gate.rs"]
pub mod callbundle_preflight_gate;

#[path = "anchors/adaptive_winloss_gas_aggression.rs"]
pub mod adaptive_winloss_gas_aggression;

#[path = "anchors/startup_clock_drift_guard.rs"]
pub mod startup_clock_drift_guard;

#[path = "anchors/dynamic_gas_escrow_solvency.rs"]
pub mod dynamic_gas_escrow_solvency;

#[path = "anchors/payload_calldata_decryption.rs"]
pub mod payload_calldata_decryption;

#[path = "anchors/builder_micro_latency_profiling.rs"]
pub mod builder_micro_latency_profiling;

#[path = "anchors/config_hot_swap_watcher.rs"]
pub mod config_hot_swap_watcher;

#[path = "anchors/local_circuit_breakers.rs"]
pub mod local_circuit_breakers;

#[path = "anchors/presimulation_probe_filter.rs"]
pub mod presimulation_probe_filter;

#[path = "anchors/greedy_scheduler_bundle_merge.rs"]
pub mod greedy_scheduler_bundle_merge;
