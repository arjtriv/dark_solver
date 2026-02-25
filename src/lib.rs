//! Dark Solver library surface.
//!
//! Public documentation and the primary operator workflow are centered on single-target
//! symbolic auditing (`src/bin/deep_sniper.rs` + `analyze_target.sh`).
//! Additional modules below are retained for internal orchestration, compatibility, and
//! research tooling used by non-primary binaries.

// Primary audit/research surface
pub mod core;
pub mod engine;
pub mod error;
pub mod fork_db;
pub mod knowledge;
pub mod protocols;
pub mod solver;
pub mod storage;
pub mod symbolic;
pub mod tactics;
pub mod utils;

// Internal / compatibility modules (not part of the primary documented workflow)
#[doc(hidden)]
pub mod basescan;
#[doc(hidden)]
pub mod defillama;
#[doc(hidden)]
pub mod executor;
#[doc(hidden)]
pub mod hand;
#[doc(hidden)]
pub mod runtime;
#[doc(hidden)]
pub mod scanner;
#[doc(hidden)]
pub mod strategies;
#[doc(hidden)]
pub mod target_queue;

pub mod config {
    pub mod chains;
}
