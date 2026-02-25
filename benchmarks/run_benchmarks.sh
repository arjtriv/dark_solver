#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_DIR="${1:-${ROOT_DIR}/benchmarks/targets}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="${ROOT_DIR}/benchmarks/results/${TIMESTAMP}"
SUMMARY_FILE="${RESULTS_DIR}/summary.tsv"

read_toml_string() {
  local file="$1"
  local key="$2"
  sed -n "s/^${key} = \"\\(.*\\)\"$/\\1/p" "${file}" | head -n 1
}

read_toml_int() {
  local file="$1"
  local key="$2"
  sed -n "s/^${key} = \\([0-9][0-9]*\\)$/\\1/p" "${file}" | head -n 1
}

if [[ ! -d "${MANIFEST_DIR}" ]]; then
  echo "manifest directory not found: ${MANIFEST_DIR}" >&2
  exit 1
fi

mkdir -p "${RESULTS_DIR}"
printf "name\taddress\tchain_id\tstatus\tlog\n" > "${SUMMARY_FILE}"

manifests=()
while IFS= read -r manifest; do
  manifests+=("${manifest}")
done < <(find "${MANIFEST_DIR}" -maxdepth 1 -name '*.toml' | sort)
if [[ ${#manifests[@]} -eq 0 ]]; then
  echo "no benchmark manifests found in ${MANIFEST_DIR}" >&2
  exit 1
fi

echo "[benchmarks] running ${#manifests[@]} target manifests"
echo "[benchmarks] results_dir=${RESULTS_DIR}"

for manifest in "${manifests[@]}"; do
  name="$(read_toml_string "${manifest}" "name")"
  address="$(read_toml_string "${manifest}" "address")"
  chain_id="$(read_toml_int "${manifest}" "chain_id")"
  expected_surface="$(read_toml_string "${manifest}" "expected_surface")"
  notes="$(read_toml_string "${manifest}" "notes")"
  base_name="$(basename "${manifest}" .toml)"
  log_file="${RESULTS_DIR}/${base_name}.log"

  if [[ -z "${name}" || -z "${address}" || -z "${chain_id}" ]]; then
    echo "[benchmarks] malformed manifest: ${manifest}" >&2
    printf "%s\t%s\t%s\t%s\t%s\n" "${name:-unknown}" "${address:-missing}" "${chain_id:-missing}" "invalid-manifest" "${log_file}" >> "${SUMMARY_FILE}"
    continue
  fi

  {
    echo "[benchmarks] manifest=${manifest}"
    echo "[benchmarks] name=${name}"
    echo "[benchmarks] address=${address}"
    echo "[benchmarks] chain_id=${chain_id}"
    echo "[benchmarks] expected_surface=${expected_surface}"
    echo "[benchmarks] notes=${notes}"
    echo
    "${ROOT_DIR}/analyze_target.sh" "${address}" "${chain_id}"
  } > "${log_file}" 2>&1 && status="ok" || status="failed"

  printf "%s\t%s\t%s\t%s\t%s\n" "${name}" "${address}" "${chain_id}" "${status}" "${log_file}" >> "${SUMMARY_FILE}"
  echo "[benchmarks] ${name}: ${status}"
done

echo "[benchmarks] wrote summary to ${SUMMARY_FILE}"
