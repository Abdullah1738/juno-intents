#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENT_FILE="${ROOT}/deployments.json"
DEPLOYMENT_NAME=""
PAYER_KEYPAIR="${JUNO_E2E_SOLVER_KEYPAIR:-}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/solana/validate-deployment-image-ids.sh --deployment <name> --payer-keypair <path> [--deployment-file <path>]

Notes:
  - Sends 2 intentionally-failing transactions (preflight simulation) to ensure the on-chain ORP + receipt-verifier
    programs accept the repo's current zkVM method IDs. No state should be committed.
  - Requires a funded devnet keypair for transaction fees.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --deployment)
      DEPLOYMENT_NAME="${2:-}"; shift 2 ;;
    --deployment-file)
      DEPLOYMENT_FILE="${2:-}"; shift 2 ;;
    --payer-keypair)
      PAYER_KEYPAIR="${2:-}"; shift 2 ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${DEPLOYMENT_NAME}" ]]; then
  echo "--deployment is required" >&2
  exit 2
fi
if [[ -z "${PAYER_KEYPAIR}" ]]; then
  echo "--payer-keypair is required" >&2
  exit 2
fi
if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  echo "deployment file not found: ${DEPLOYMENT_FILE}" >&2
  exit 1
fi
if [[ ! -f "${PAYER_KEYPAIR}" ]]; then
  echo "payer keypair not found: ${PAYER_KEYPAIR}" >&2
  exit 2
fi

need_cmd() {
  if ! command -v "$1" >/dev/null; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd go

cd "${ROOT}"
go run ./cmd/juno-intents validate-image-ids \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --payer-keypair "${PAYER_KEYPAIR}"
