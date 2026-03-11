# Use Cases

## 1. Single-Contract Deep Triage (Primary Workflow)

Goal:
analyze one contract with constraint-backed depth beyond static checks and basic fuzzing.

Input:
- contract address
- RPC endpoint
- optional chain id

Command:

```bash
./analyze_target.sh <contract_address> [chain_id]
```

Output:
- objective findings with reproducible parameters
- feasible call paths and per-step calldata
- replay/verification status for candidate findings
- log and telemetry artifacts for audit writeups

Value:
- exposes guarded multi-step risk paths
- produces reproducible evidence for manual review
- supports deterministic regression re-analysis as the target evolves

## 2. Security Research Reproduction

Goal: re-run analysis with fixed configuration and compare outputs.

Workflow:
1. Pin RPC endpoint and chain id.
2. Run identical target analysis with the same objective controls.
3. Compare finding set, path details, and replay outcomes.

Pinned replay helper:

```bash
cargo run --bin shadow_replay -- \
  --rpc-url "$ETH_RPC_URL" \
  --chain-id <chain_id> \
  --address <contract_address> \
  --block-number <block_number>
```

Value:
- supports deterministic research notes
- improves confidence in triage decisions
- provides a stable baseline for pre/post-mitigation comparison

## 3. Local Operator Session Hardening

Goal: choose healthier RPC infrastructure, run the audit, then confirm the session stayed within
the expected memory and solve-budget envelope.

Workflow:
1. Benchmark candidate RPC providers.
2. Run `deep_sniper` or `shadow_replay` against the target.
3. Inspect `pressure_report` before treating the output as a stable local baseline.

Commands:

```bash
cargo run --bin benchmark_rpc -- --json
cargo run --bin pressure_report -- --window-secs 3600 --json
```

Value:
- catches weak RPC endpoints before they pollute replay timings
- turns runtime pressure into an explicit review artifact
- makes repeated local runs easier to compare across days
