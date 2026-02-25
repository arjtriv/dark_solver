# Dark Solver

Constraint-driven single-target EVM auditing with symbolic execution and Z3, built for reproducible manual security review.

## Overview

Dark Solver is a single-target EVM auditing tool focused on deterministic, solver-backed security analysis.
It ingests contract bytecode and chain state, runs protocol-aware symbolic objectives, and emits reproducible findings for manual review.

## Scope

| Category | Summary |
| --- | --- |
| Purpose | Audit one EVM contract at a time from bytecode and chain state |
| Inputs | Contract address, RPC endpoint, chain id |
| Core method | Symbolic execution + Z3 (`QF_ABV`) + objective/invariant gates |
| Output | Structured candidate findings, calldata/steps, solver parameters, telemetry artifacts |
| Runtime posture | Simulation-first workflow (no public transaction submission path) |

## Quick Start

```bash
cp .env.example .env
# set ETH_RPC_URL in .env
./analyze_target.sh <contract_address> [chain_id]
```

Example output:

```text
[AUDIT] target=0x...
[AUDIT] bytecode=... bytes
[AUDIT] solve_complete elapsed_ms=...
[AUDIT] objective=...
  step=1 target=0x... calldata=0x...
```

Primary artifacts:
- `logs/target_analysis.log`
- `telemetry/` (when enabled)

## Why It Is Technically Distinct

- EVM-width-correct arithmetic modeling, including 256-bit and 512-bit invariant math.
- Bounded symbolic search controls (loop/PC caps, dead-end pruning, bounded symbolic loops).
- Keccak/storage structure reasoning with SHA3 trace capture and deep projection constraints.
- Proxy-aware hydration (implementation/beacon/diamond facet expansion) with bounded depth.
- Proof/slice reuse layers (selector memoization, bytecode-slice cache, SimHash-assisted reuse).
- Fail-closed parallel objective execution with explicit SAT/UNSAT/timeout accounting.
- Deterministic replay/verification path for audit evidence quality.

## Workflow

```mermaid
flowchart LR
    A["Target + RPC"] --> B["Hydration (bytecode, storage, proxy context)"]
    B --> C["Objective Catalog"]
    C --> D["Symbolic Execution + Z3"]
    D --> E["Invariant / Sanity Gates"]
    E --> F["Replay Validation (optional)"]
    F --> G["Findings + Logs + Telemetry"]
```

## Where It Fits

| Workflow | Strength | Weakness |
| --- | --- | --- |
| Static analyzers | Fast broad pattern coverage | Limited depth on guarded state transitions |
| Fuzzers | Strong runtime signal | Less deterministic coverage for narrow constraints |
| Dark Solver | Constraint-proven multi-step feasibility + invariant gating + replay evidence | Not complete path coverage; depends on RPC/chain data quality |

## Full Technical Differentiators (Implemented)

<details>
<summary><strong>Open Full Technical Inventory</strong> (math, modeling, search, hydration, validation, RPC, telemetry)</summary>

### Constraint semantics and numerical correctness

- Deterministic solver setup: explicit `QF_ABV` logic, timeout, resource limit, partial models, and fixed random seed.
- Width-correct symbolic arithmetic helpers: unsigned/signed division and remainder with EVM-compatible division-by-zero behavior across 256-bit and 512-bit bit-vectors.
- 256-bit to 512-bit widening for invariant math: cross-multiplication comparisons avoid modular wrap-around artifacts when comparing ratios and reserve products.
- Overflow-safe ratio gates: basis-point drift checks expressed as cross-products (no floating-point arithmetic).
- Explicit reserve-width normalization: AMM reserve components are masked/extracted to uint112-compatible values before invariant comparisons.
- Symbolic `EXP` optimization: exponentiation-by-squaring fast path for concrete exponents, 256-step symbolic fallback otherwise.
- Symbolic `BYTE` / `SIGNEXTEND` helpers: reusable opcode semantics in shared math helpers.
- Address-word normalization: canonical 160-bit address semantics inside 256-bit words.

### Symbolic execution search control (path explosion mitigation)

- Loop-iteration caps per PC: repeated visits beyond configured limits are cut off by marking the branch as reverted.
- Visited-PC cardinality cap: branch exploration stops when visited PC state exceeds configured bounds.
- Dead-end PC pruning: bytecode pre-scan identifies unconditional revert/invalid sinks and common revert-handler shapes.
- Bounded symbolic data loops: symbolic lengths are clamped via `bounded_len` with fail-closed defaults for non-concrete lengths.
- Gas feasibility constraints during execution: symbolic gas deduction with `gas_remaining >= 0` constraint.
- Reentrancy-targeted pruning: reentrancy branches retained only when they affect tracked solvency/invariant-relevant state.
- Fail-closed stack/memory edge handling: underflow/decode failures become terminal branch failures.

### Keccak and storage structure modeling (beyond opaque hashing)

- Size-specialized Keccak UFs: `keccak_32`, `keccak_64`, `keccak_96`, `keccak_128`.
- SHA3 trace capture: preimage chunks, hash term, size, and program counter are recorded for traced hash operations.
- Storage pattern inference: SHA3 traces are analyzed to infer flat mappings, nested mappings, dynamic arrays, and struct-offset patterns.
- Deep storage projection constraints: implication chains link concrete hash matches to concrete key material across nested mapping levels.
- Dual storage representation (shadow algebraic storage): flat storage plus shadow `Array<Key, Value>` representation for pattern-resolved accesses.
- Pattern-resolved abstract keys: nested mapping keys are concatenated into abstract keys for structured reads/writes instead of only raw `keccak(key . slot)` slots.

### Proof reuse, bytecode normalization, and hydration acceleration

- Bytecode-selector proof memoization: `SAT` / `UNSAT` / `TIMEOUT` cached by normalized bytecode fingerprint + selector (memory + optional on-disk persistence).
- Constructor-tail normalization in fingerprints: runtime-equivalent forks can reuse proof results.
- Batch UNSAT caching: selector sets can be marked `UNSAT` in one write path.
- Bytecode slice caching: selector discovery / callback discovery / dead-end-PC scans cached per bytecode hash.
- SimHash-assisted slice reuse: nearby bytecode templates can seed slice reuse and are promoted to exact-hash cache entries.
- Deep-scan preloader state cache: tracked token/account state can be preloaded and cached to reduce repeated hydration RPC work.
- Proxy-aware bytecode hydration: setup resolves EIP-1967 implementation, EIP-1967 beacon, EIP-897 `implementation()`, and diamond facets; scan slices are merged across resolved implementations/facets.
- Bounded proxy expansion: proxy depth, facet counts, and merged selector lists are explicitly bounded.

### Objective execution architecture and audit-oriented coverage reporting

- Parallel objective execution with isolated Z3 contexts (`spawn_blocking`) to avoid cross-objective solver contamination and `Send` issues.
- Fail-closed parallel runner: worker panics/cancellations surface as errors instead of partial silent success.
- Detailed objective run records: audit-oriented runner mode records per-objective status (`SAT`, `UNSAT`, `Panic`, `Timeout`) and elapsed time.
- Optional total solve timeout with pending-objective timeout attribution in detailed runner mode.

### Candidate quality gates and replay validation

- Triple-gate invariant admission (`Solvency ∧ PriceSanity ∧ KConstraint`) for SAT candidate filtering.
- Baseline reserve caching in invariant checker to reduce redundant database reads.
- Solve-phase slippage gate (optional): Uniswap v3 exact-input paths can be checked against quoter output before returning SAT candidates.
- Replay validation path: candidate paths are simulated on pinned state with structured success/profitability/error fields.
- Mark-to-market result accounting: replay reports track ETH/token deltas, priced vs unpriced tokens, stale price counts, and gas-cost-adjusted value changes.
- Structured revert/halt decoding: Solidity `Error(string)` and `Panic(uint256)` payload decoding for audit evidence quality.

### RPC resilience and real-world operability

- Multi-endpoint hydration provider pool.
- Per-endpoint cooldowns for rate-limited providers.
- Global rate-limit cooldown signaling across non-pooled retry paths.
- Retryability classification (retryable vs non-retryable RPC errors).
- Retry-After parsing and cooldown hint usage.
- Bounded exponential backoff.
- Per-attempt timeout control (including longer timeouts for large full-block hydration).
- Tolerant full-block decoding path for partially unparseable transaction payloads.

### Instrumentation and reproducibility support

- Objective/solver telemetry scopes for target/objective traceability.
- Async buffered telemetry writes to reduce write amplification during active runs.
- Binary + JSONL telemetry persistence for dashboards and offline analysis.
- Rolling operational verdict metrics (memory leak and solve-rate windows).

</details>

## Repository Layout (High-Signal Paths)

- `src/bin/deep_sniper.rs`: primary single-target audit entrypoint
- `src/symbolic/`: symbolic EVM engine and opcode modeling
- `src/tactics/objectives/`: protocol/risk objective definitions
- `src/solver/setup.rs`: target hydration and scenario setup
- `src/solver/runner.rs`: parallel objective execution
- `src/solver/invariants.rs`: invariant admission/gating
- `src/executor/verifier.rs`: replay verification logic used for validation

## Safety and Runtime Posture

- Simulation-only build
- Public workflow does not submit transactions
- Submission mode is disabled in config loading for this build
- Deterministic `.env`-driven configuration for reproducible analysis runs

## Limitations (Explicit)

- No guarantee of complete path coverage for arbitrary contracts
- RPC quality and chain state availability affect hydration and replay reliability
- Some internal API names are retained for compatibility with earlier integrations

## Quality Gates (Local Validation)

```bash
cargo fetch --locked
cargo check --release
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --release
```

## Release Checklist

- `cargo check --release` passes
- `cargo clippy --workspace --all-targets --release -- -D warnings` passes
- `cargo test --release` passes
- README, SETUP, and docs reflect the current public workflow and output

## Documentation

- [SETUP.md](SETUP.md)
- [docs/README.md](docs/README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/OPERATIONS.md](docs/OPERATIONS.md)
- [docs/USE_CASES.md](docs/USE_CASES.md)
- [docs/CASE_STUDY_TEMPLATE.md](docs/CASE_STUDY_TEMPLATE.md)
