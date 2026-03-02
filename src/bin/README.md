# Binaries

## Primary entrypoint

- `deep_sniper.rs`: single-target audit runner used by `./analyze_target.sh`

## Supporting binaries

Other binaries in this directory support replay, benchmarking, and operator diagnostics. They are
not required for the primary public workflow documented in the repository README.

- `shadow_replay.rs`: rerun a target at a pinned historical block using named flags
- `benchmark_rpc.rs`: compare candidate RPC endpoints and choose the lowest-latency default
- `pressure_report.rs`: summarize runtime memory and solve-budget pressure over a fixed window
