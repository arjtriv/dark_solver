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

Value:
- supports deterministic research notes
- improves confidence in triage decisions
- provides a stable baseline for pre/post-mitigation comparison
