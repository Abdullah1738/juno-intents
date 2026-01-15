#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

SECRET_NAME="JUNO_RECEIPT_WITNESS_HEX"
OUT_DIR="${ROOT}/tmp/witness"
OUT_FILE="${OUT_DIR}/${SECRET_NAME}"
LOG_FILE="${OUT_DIR}/wallet_witness_v1.log"

DEPLOYMENT_ID_HEX=""
FILL_ID_HEX=""

TXID_HEX=""
ACTION_INDEX=""

REF="${REF:-main}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/gh/update-receipt-witness-secret.sh [--txid <hex>] [--action <u32>] [--ref <git-ref>]

Notes:
  - Generates a real ReceiptWitnessV1 from your local JunoCash wallet/node.
  - Writes the witness hex to tmp/ (untracked) and updates the GitHub Actions secret:
      JUNO_RECEIPT_WITNESS_HEX
  - The witness is bound to the deterministic test Fill PDA used by Solana program-test:
      deployment_id = 0x11..11 (32 bytes)
      intent_nonce  = 0x33..33 (32 bytes)
      iep_program   = 0xA1..A1 (32 bytes)
      fill_id       = pda(fill)
  - Does NOT print the witness hex to stdout/stderr.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --txid)
      TXID_HEX="${2:-}"; shift 2 ;;
    --action)
      ACTION_INDEX="${2:-}"; shift 2 ;;
    --ref)
      REF="${2:-}"; shift 2 ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -n "${TXID_HEX}" && -z "${ACTION_INDEX}" ]]; then
  echo "--action is required when --txid is set" >&2
  exit 2
fi
if [[ -z "${TXID_HEX}" && -n "${ACTION_INDEX}" ]]; then
  echo "--txid is required when --action is set" >&2
  exit 2
fi

if ! command -v gh >/dev/null; then
  echo "missing required command: gh" >&2
  exit 1
fi
if ! command -v go >/dev/null; then
  echo "missing required command: go" >&2
  exit 1
fi
if ! command -v cargo >/dev/null; then
  echo "missing required command: cargo" >&2
  exit 1
fi

DEPLOYMENT_ID_HEX="$(printf '11%.0s' {1..32})"
INTENT_NONCE_HEX="$(printf '33%.0s' {1..32})"
IEP_PROGRAM_ID_HEX="$(printf 'a1%.0s' {1..32})"

FILL_ID_HEX="$(
  cd "${ROOT}" \
    && go run ./cmd/juno-intents pda \
      --program-id "${IEP_PROGRAM_ID_HEX}" \
      --deployment-id "${DEPLOYMENT_ID_HEX}" \
      --intent-nonce "${INTENT_NONCE_HEX}" \
      --print fill-id-hex
)"

mkdir -p "${OUT_DIR}"
umask 077

WITNESS_ARGS=(
  --deployment-id "${DEPLOYMENT_ID_HEX}"
  --fill-id "${FILL_ID_HEX}"
)
if [[ -n "${TXID_HEX}" ]]; then
  WITNESS_ARGS+=(--txid "${TXID_HEX}" --action "${ACTION_INDEX}")
fi

cd "${ROOT}"
cargo run --release --locked --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  "${WITNESS_ARGS[@]}" \
  >"${OUT_FILE}" 2>"${LOG_FILE}"
chmod 600 "${OUT_FILE}" "${LOG_FILE}" || true

gh secret set "${SECRET_NAME}" --app actions < "${OUT_FILE}"

echo "updated_secret=${SECRET_NAME}"
echo "witness_file=${OUT_FILE}"
echo "log_file=${LOG_FILE}"

echo "triggering groth16 workflow (witness_source=secret, ref=${REF})..." >&2
gh workflow run groth16.yml -f witness_source=secret --ref "${REF}" >/dev/null
