# Setup

## Fast Path (Recommended)

```bash
cp .env.example .env
# set ETH_RPC_URL in .env
./analyze_target.sh <contract_address> [chain_id]
```

Expected console markers:
- `[AUDIT] target=...`
- `[AUDIT] bytecode=... bytes`
- `[AUDIT] solve_complete ...`

Primary log file:
- `logs/target_analysis.log`

## Prerequisites

- Rust `1.93.0` (pinned in `rust-toolchain.toml`)
- EVM RPC endpoint

## 1. Configure Environment

```bash
cp .env.example .env
```

Required keys:
- `ETH_RPC_URL`
- `CHAIN_ID` (optional if you pass it to `./analyze_target.sh`)

Notes:
- This build is simulation-only (transaction submission mode is disabled).
- The primary workflow is `./analyze_target.sh`; other binaries are supporting utilities.

## 2. Analyze a Single Contract (Primary Workflow)

```bash
./analyze_target.sh <contract_address> [chain_id]
```

Example:

```bash
./analyze_target.sh 0x0000000000000000000000000000000000000000 1
```

Output log:
- `logs/target_analysis.log`

Help:

```bash
./analyze_target.sh --help
```

Common setup errors:
- `cargo is required but was not found in PATH`
  - Install Rust via `rustup`, then reopen your shell.
- `ETH_RPC_URL must be set`
  - Copy `.env.example` to `.env` and set a real RPC endpoint.
- `ETH_RPC_URL ... CHANGE_ME`
  - Replace the placeholder value in `.env`.
- `Invalid contract address`
  - Pass a checksummed or lowercase `0x...` address with 40 hex characters.

## 3. Quality Gates

```bash
cargo fetch --locked
cargo check --release
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --release
```

Pre-push recommendation:
- run all four commands above in order
- ensure `./analyze_target.sh <contract_address> [chain_id]` still produces expected `[AUDIT]` markers

## 4. Cleanup

```bash
bash scripts/clean_workspace.sh
```

Deep cleanup:

```bash
bash scripts/clean_workspace.sh --deep
```
