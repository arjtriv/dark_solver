# DarkSolver: A Formal Verification Primitive for EVM State Invariants

[![CI](https://github.com/arjtriv/dark_solver/actions/workflows/ci.yml/badge.svg)](https://github.com/arjtriv/dark_solver/actions/workflows/ci.yml)

DarkSolver is a simulation-first auditing primitive for EVM contracts. It couples SMT-backed symbolic execution using Z3's `QF_ABV` logic with protocol-aware objective selection, storage-pattern reasoning, and replay-based validation so a reviewer sees feasible exploit evidence instead of heuristic lint.

## Architecture Summary

- Solver core: symbolic EVM execution with width-correct bit-vector semantics, bounded path search, and fail-closed branch handling.
- Storage reasoning: SHA3 trace capture plus inferred mapping and dynamic-array structure instead of treating `keccak256` as opaque noise.
- Audit output: reproducible calldata sequences, objective names, invariant gate outcomes, and replay summaries suitable for a security report.
- Runtime posture: simulation-only public workflow. The repository is positioned as an auditing research primitive, not an execution bot.
- Research surface: architecture docs, a technical overview PDF, benchmark harnesses, and example findings are all versioned in-repo.

## Found Vulnerabilities

The repository includes researcher-style sample outputs instead of hand-wavy screenshots.

- Critical: initialization race on an upgradeable proxy fixture.
  See [reports/critical_initialization_race.md](reports/critical_initialization_race.md).

Example finding excerpt:

```text
Severity: Critical
Objective: Initialization Race
Signal: initializer guard reachable before owner slot is sealed
Witness: 2-call path admitted by replay and invariant gates
Impact: attacker captures privileged control before expected administrator setup
```

## Quick Start

```bash
cp .env.example .env
# set ETH_RPC_URL in .env
./analyze_target.sh <contract_address> [chain_id]
```

Primary artifacts:

- `logs/target_analysis.log`
- `telemetry/` when enabled
- `reports/` for curated example writeups

Companion tooling:

- `cargo run --bin shadow_replay -- --rpc-url "$ETH_RPC_URL" --chain-id <id> --address <0x...> --block-number <n>`
- `cargo run --bin benchmark_rpc -- --json`
- `cargo run --bin pressure_report -- --window-secs 3600 --json`

## Research Output

- [docs/technical_overview.pdf](docs/technical_overview.pdf): yellowpaper-style overview of the symbolic state transition function, storage abstractions, and Keccak modeling.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): component-level architecture and data flow.
- [research/README.md](research/README.md): scratch space for exploratory Z3 notes, benchmark drafts, and pre-paper material.
- [reports/README.md](reports/README.md): format and intent for publishable finding writeups.

## Benchmark Harness

DarkSolver now ships with a benchmark harness under [benchmarks/](benchmarks/README.md). The harness is designed for SCONE-style manifest-driven evaluation and currently includes curated live-target starter manifests so reviewers can run the workflow immediately:

```bash
./benchmarks/run_benchmarks.sh
```

Starter manifests cover:

- Lending / comptroller surfaces
- AMM / pool-manager surfaces
- Factory and deployment surfaces
- High-value vault / routing surfaces

Benchmark logs are written to `benchmarks/results/<timestamp>/`.

## Repository Surface

| Path | Purpose |
| --- | --- |
| `src/` | Core Rust engine, symbolic executor, objective catalog, verifier |
| `research/` | Exploratory Z3 notes, draft experiments, future notebook spillover |
| `benchmarks/` | Manifest-driven benchmark harness and starter targets |
| `docs/` | Architecture, operations, and technical-overview PDF |
| `reports/` | Example exploit and finding writeups |
| `.github/` | CI workflow for build/test signals |
| `tests/` | Regression anchors and solver behavior tests |

## Technical Differentiators

- Z3 `QF_ABV` solver configuration with deterministic settings, bounded resource usage, and parallel objective isolation.
- EVM-width-correct arithmetic over 256-bit and 512-bit bit-vectors for reserve math, ratio comparisons, and invariant gates.
- SHA3 trace capture with structured storage pattern inference for flat mappings, nested mappings, and dynamic arrays.
- Proxy-aware hydration with bounded expansion across implementation, beacon, and facet-based proxy layouts.
- Replay/invariant validation for candidate findings so SAT results are gated by operational plausibility.
- Fail-closed handling across config parsing, discovery feeds, startup probes, and queue prioritization.

## Quality Gates

```bash
cargo fetch --locked
cargo check --release
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --release
```

Focused smoke tests used by CI:

```bash
cargo test --quiet --test anchors startup_rpc_probe_validated_config
cargo test --quiet --test anchors discovery_decode_fail_closed
cargo test --quiet --test anchors priority_hot_lane_ingestion
cargo test --quiet decode_abi_
cargo test --quiet target_queue_promotes
```

## Documentation

- [SETUP.md](SETUP.md)
- [docs/README.md](docs/README.md)
- [src/bin/README.md](src/bin/README.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/OPERATIONS.md](docs/OPERATIONS.md)
- [docs/USE_CASES.md](docs/USE_CASES.md)
- [docs/CASE_STUDY_TEMPLATE.md](docs/CASE_STUDY_TEMPLATE.md)
- [docs/technical_overview.pdf](docs/technical_overview.pdf)
