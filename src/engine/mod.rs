//! Compatibility namespace that preserves historical `engine::*` import paths
//! while forwarding to the current solver modules.

pub use crate::solver::heuristics;
pub use crate::solver::invariants;
pub use crate::solver::memo;
pub mod objective_catalog;
pub use crate::solver::objectives;
pub use crate::solver::oracle_manipulation;
pub use crate::solver::runner;
pub use crate::solver::setup;
pub use crate::solver::soundness;
pub use crate::solver::telemetry;
pub use crate::solver::verification;
