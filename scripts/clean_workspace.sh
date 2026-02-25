#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

DEEP_CLEAN="false"
if [[ "${1:-}" == "--deep" ]]; then
    DEEP_CLEAN="true"
fi

# Remove generated/local artifacts that should not appear in portfolio branches.
rm -rf logs
rm -rf telemetry/*.jsonl telemetry/*.json 2>/dev/null || true
rm -rf artifacts/backups 2>/dev/null || true
rm -f crash_report_*.json
rm -f contracts.db
rm -rf scripts/__pycache__
rm -f .DS_Store

if [[ "${DEEP_CLEAN}" == "true" ]]; then
    rm -rf target .tmp_build tmp_build
fi

# Keep source tree deterministic for public review.
mkdir -p logs telemetry artifacts

if [[ "${DEEP_CLEAN}" == "true" ]]; then
    echo "Workspace cleanup complete (deep mode)."
else
    echo "Workspace cleanup complete."
fi
