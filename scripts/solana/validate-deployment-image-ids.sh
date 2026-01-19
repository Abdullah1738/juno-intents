#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENT_FILE="${ROOT}/deployments.json"
DEPLOYMENT_NAME=""

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/solana/validate-deployment-image-ids.sh --deployment <name> [--deployment-file <path>]

Notes:
  - Downloads on-chain Solana program binaries and checks that they embed the expected RISC0 method image IDs.
  - Intended to fail fast when a base deployment is out-of-sync with the repo's current zkVM methods.
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
if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  echo "deployment file not found: ${DEPLOYMENT_FILE}" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd python3
need_cmd solana

DEPLOY_ENV="$(
  python3 - "${DEPLOYMENT_FILE}" "${DEPLOYMENT_NAME}" <<'PY'
import json,sys
path=sys.argv[1]
name=sys.argv[2]
with open(path,"r",encoding="utf-8") as f:
  reg=json.load(f)
entry=None
for it in (reg.get("deployments") or []):
  if it.get("name")==name:
    entry=it
    break
if entry is None:
  raise SystemExit(f"deployment not found: {name}")
def emit(k, v):
  if v is None:
    return
  print(f"{k}={v}")
emit("RPC_URL", entry.get("rpc_url"))
emit("ORP_PROGRAM_ID", entry.get("operator_registry_program_id"))
emit("RV_PROGRAM_ID", entry.get("receipt_verifier_program_id"))
PY
)"

while IFS='=' read -r k v; do
  export "${k}=${v}"
done <<<"${DEPLOY_ENV}"

if [[ -z "${RPC_URL:-}" || -z "${ORP_PROGRAM_ID:-}" || -z "${RV_PROGRAM_ID:-}" ]]; then
  echo "deployment missing required fields (rpc_url/operator_registry_program_id/receipt_verifier_program_id)" >&2
  printf '%s\n' "${DEPLOY_ENV}" >&2
  exit 1
fi

EXPECTED_ORP_IMAGE_ID="$(
  python3 - "${ROOT}/solana/operator-registry/src/lib.rs" <<'PY'
import re,sys
path=sys.argv[1]
raw=open(path,"r",encoding="utf-8").read()
m=re.search(r"const\s+EXPECTED_IMAGE_ID\s*:\s*\[u8;\s*32\]\s*=\s*\[(.*?)\];", raw, re.S)
if not m:
  raise SystemExit(f"EXPECTED_IMAGE_ID not found in {path}")
hex_bytes=re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
if len(hex_bytes) != 32:
  raise SystemExit(f"EXPECTED_IMAGE_ID parse error in {path}: expected 32 bytes, got {len(hex_bytes)}")
print("".join(hex_bytes).lower())
PY
)"

EXPECTED_RV_IMAGE_ID="$(
  python3 - "${ROOT}/solana/receipt-verifier/src/lib.rs" <<'PY'
import re,sys
path=sys.argv[1]
raw=open(path,"r",encoding="utf-8").read()
m=re.search(r"const\s+EXPECTED_IMAGE_ID\s*:\s*\[u8;\s*32\]\s*=\s*\[(.*?)\];", raw, re.S)
if not m:
  raise SystemExit(f"EXPECTED_IMAGE_ID not found in {path}")
hex_bytes=re.findall(r"0x([0-9a-fA-F]{2})", m.group(1))
if len(hex_bytes) != 32:
  raise SystemExit(f"EXPECTED_IMAGE_ID parse error in {path}: expected 32 bytes, got {len(hex_bytes)}")
print("".join(hex_bytes).lower())
PY
)"

TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMPDIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

dump_and_check() {
  local label="$1"
  local program_id="$2"
  local expected_hex="$3"
  local out_so="$4"

  echo "dumping ${label} program: ${program_id}" >&2
  solana -u "${RPC_URL}" program dump "${program_id}" "${out_so}" >/dev/null

  python3 - "${label}" "${program_id}" "${expected_hex}" "${out_so}" <<'PY'
import sys
label=sys.argv[1]
program_id=sys.argv[2]
expected_hex=sys.argv[3].strip().lower()
path=sys.argv[4]
expected=bytes.fromhex(expected_hex)
data=open(path,"rb").read()
if expected in data:
  print(f"{label}: ok (program_id={program_id} expected_image_id={expected_hex})")
  raise SystemExit(0)
print(f"{label}: mismatch (program_id={program_id} expected_image_id={expected_hex})", file=sys.stderr)
raise SystemExit(1)
PY
}

ok=true
if ! dump_and_check "operator-registry" "${ORP_PROGRAM_ID}" "${EXPECTED_ORP_IMAGE_ID}" "${TMPDIR}/orp.so"; then
  ok=false
fi
if ! dump_and_check "receipt-verifier" "${RV_PROGRAM_ID}" "${EXPECTED_RV_IMAGE_ID}" "${TMPDIR}/rv.so"; then
  ok=false
fi

if [[ "${ok}" != "true" ]]; then
  echo "base deployment appears out of sync with the repo's current zkVM image IDs." >&2
  echo "fix: redeploy Solana programs and update deployments.json to point to the new program IDs." >&2
  exit 1
fi
