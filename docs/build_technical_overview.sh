#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/.latexmk"
mkdir -p "${BUILD_DIR}"

latexmk \
  -pdf \
  -quiet \
  -interaction=nonstopmode \
  -halt-on-error \
  -output-directory="${BUILD_DIR}" \
  "${SCRIPT_DIR}/technical_overview.tex"

cp "${BUILD_DIR}/technical_overview.pdf" "${SCRIPT_DIR}/technical_overview.pdf"
echo "Wrote ${SCRIPT_DIR}/technical_overview.pdf"
