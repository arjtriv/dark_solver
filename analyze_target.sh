#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

print_usage() {
  cat >&2 <<'EOF'
Usage:
  ./analyze_target.sh <contract_address> [chain_id]

Description:
  Runs the primary single-target audit workflow (simulation-first) against one contract.

Requirements:
  - Rust toolchain installed
  - ETH_RPC_URL set in .env or environment

Examples:
  ./analyze_target.sh 0x1111111111111111111111111111111111111111
  ./analyze_target.sh 0x1111111111111111111111111111111111111111 1
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  print_usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  print_usage
  exit 2
fi

TARGET_ADDRESS="$1"
CHAIN_ID_OVERRIDE="${2:-}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source ./.env
  set +a
fi

CHAIN_ID_RESOLVED="${CHAIN_ID_OVERRIDE:-${CHAIN_ID:-1}}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required but was not found in PATH." >&2
  echo "Install Rust (rustup) and retry." >&2
  exit 1
fi

if [[ -z "${ETH_RPC_URL:-}" ]]; then
  echo "ETH_RPC_URL must be set in .env (or environment)." >&2
  if [[ ! -f .env ]]; then
    echo "Quick start: cp .env.example .env && edit ETH_RPC_URL" >&2
  fi
  exit 1
fi

if [[ "${ETH_RPC_URL}" == *"CHANGE_ME"* ]]; then
  echo "ETH_RPC_URL in .env still contains the placeholder value. Set a real RPC endpoint." >&2
  exit 1
fi

if [[ ! "${TARGET_ADDRESS}" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
  echo "Invalid contract address: ${TARGET_ADDRESS}" >&2
  echo "Expected 20-byte hex address (0x + 40 hex chars)." >&2
  exit 1
fi

if [[ ! "${CHAIN_ID_RESOLVED}" =~ ^[0-9]+$ ]]; then
  echo "Invalid chain_id: ${CHAIN_ID_RESOLVED}" >&2
  echo "Expected an unsigned integer chain id." >&2
  exit 1
fi

mkdir -p logs
LOG_FILE="logs/target_analysis.log"

echo "[analyze_target] target=${TARGET_ADDRESS} chain_id=${CHAIN_ID_RESOLVED}" | tee -a "${LOG_FILE}"
echo "[analyze_target] log=${LOG_FILE}" | tee -a "${LOG_FILE}"
cargo run --release --bin deep_sniper -- \
  --address "${TARGET_ADDRESS}" \
  --chain-id "${CHAIN_ID_RESOLVED}" \
  --rpc-url "${ETH_RPC_URL}" 2>&1 | tee -a "${LOG_FILE}"
