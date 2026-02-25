# Benchmarks

This directory contains the benchmark harness and starter target manifests for DarkSolver.

## Intent

The harness is designed around manifest-driven evaluation so the repository can ingest SCONE-style corpora or custom EVM target sets without changing the runner.

## Quick Run

```bash
./benchmarks/run_benchmarks.sh
```

Results are written to:

- `benchmarks/results/<timestamp>/summary.tsv`
- `benchmarks/results/<timestamp>/*.log`

## Manifest Format

Each target manifest is a small TOML file with the following fields:

```toml
name = "base-moonwell-comptroller"
address = "0xfBb21d0380beE3312B33c4353c8936a0F13EF26C"
chain_id = 8453
expected_surface = "lending, governance, liquidation"
notes = "Starter live target for lending-mode and bad-debt objective coverage."
```

## Starter Suite

The repository currently ships with curated live-target starter manifests that exercise major objective families while the historical vulnerable corpus is curated separately.

Included starter targets:

- Moonwell Comptroller
- Morpho Blue
- Aave V3 Pool
- Balancer Vault
- Uniswap V3 Factory
- Aerodrome Factory
