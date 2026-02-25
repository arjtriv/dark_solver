# Architecture

## Goal

Dark Solver performs simulation-only security analysis for one EVM contract at a time.

It uses symbolic execution plus SMT solving to find feasible high-risk paths and emit reproducible evidence.

## Primary Analysis Flow

1. Accept a target contract address plus RPC endpoint.
2. Fetch bytecode and hydrate target/storage context.
3. Build protocol-aware objective set for the target.
4. Run symbolic objective solvers in parallel.
5. Validate candidate findings with replay/invariant gates.
6. Emit findings plus reproducible path/parameter evidence.

## Core Components

### Target Setup (`src/solver/setup.rs`)
- fetches bytecode and chain context
- prepares symbolic scenario state and chain-aware constraints

### Objective Catalog (`src/engine/objective_catalog.rs`)
- selects protocol and invariant objectives
- applies objective allowlist/denylist controls

### Symbolic Engine (`src/symbolic/`)
- opcode-level symbolic state transitions
- keccak/preimage modeling
- path feasibility constraints over 256-bit EVM values

### Invariant Gate (`src/solver/invariants.rs`)
- admissibility checks to reject structurally invalid candidate states

### Parallel Runner (`src/solver/runner.rs`)
- executes objective modules concurrently
- collects SAT findings deterministically

### Replay / Verification (`src/executor/verifier.rs`)
- simulates candidate paths on pinned state
- confirms operational feasibility before reporting a finding

## Design Principles

- simulation-only public workflow
- deterministic and reproducible evidence
- protocol-aware objective modeling over generic pattern matching
- fail-closed behavior for uncertain states
