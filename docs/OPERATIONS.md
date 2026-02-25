# Operations Runbook

## Scope

This runbook describes the supported operational path for Dark Solver as a single-target EVM auditing tool.

Primary command path:

```bash
./analyze_target.sh <contract_address> [chain_id]
```

## Preconditions

- Rust toolchain available (`rustup` + pinned toolchain).
- `.env` present with a valid `ETH_RPC_URL`.
- Optional `CHAIN_ID` in `.env`; otherwise pass chain ID as the second CLI argument.

## Standard Operator Flow

1. Configure environment:

```bash
cp .env.example .env
```

2. Run a target audit:

```bash
./analyze_target.sh <contract_address> [chain_id]
```

3. Collect artifacts:
- Console output for objective findings and parameters.
- `logs/target_analysis.log` for review and case-study writeups.
- `telemetry/` artifacts when telemetry is enabled.

## Failure Modes and Expected Responses

- `ETH_RPC_URL must be set`:
  - Set `ETH_RPC_URL` in `.env` and rerun.
- `target has empty bytecode`:
  - Confirm the address is a contract on the requested chain.
- RPC timeout / rate-limit errors:
  - Retry with a higher-quality endpoint.
  - If multiple providers are available, rotate `ETH_RPC_URL` to a healthier endpoint.

## Safety Posture

- Public workflow is simulation-only.
- Transaction submission mode is rejected by config loading in this build.
- Outputs are for audit/research review; no automated transaction dispatch is part of the documented operator path.

## Quality Gates

Use these commands before publishing changes:

```bash
cargo check --release
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --release
```

## Recommended CI Gate

Minimum CI expectation:

```bash
cargo check --release
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --release
```
