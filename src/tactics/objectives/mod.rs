//! Modular objective registry for risk-analysis tactics.
//! The `ExploitObjective` trait name is retained for API compatibility with existing modules.

include!("core.rs");
include!("objectives_lending_oracle.rs");
include!("objectives_credit_amm.rs");
include!("objectives_entropy_governance.rs");
include!("objectives_groth16_audit.rs");
include!("objectives_proxy_logic_lag.rs");
include!("objectives_l2_bridge_arbitrage.rs");
include!("objectives_deep_analysis.rs");
include!("objectives_invariants_vaults.rs");
include!("objectives_tail_and_tests.rs");
