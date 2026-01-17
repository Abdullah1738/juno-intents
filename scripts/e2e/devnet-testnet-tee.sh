#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENT_FILE="deployments.json"
BASE_DEPLOYMENT=""

PRIORITY_LEVEL="${JUNO_E2E_PRIORITY_LEVEL:-Medium}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/e2e/devnet-testnet-tee.sh --base-deployment <name> [--deployment-file <path>]

Notes:
  - Requires Nitro Enclaves enabled on the host (/dev/nitro_enclaves).
  - Creates a fresh deployment_id + ORP/CRP/IEP config PDAs on Solana devnet.
  - Registers 2 enclave operator keys in ORP (via Groth16 attestation bundles).
  - Submits CRP observations signed by enclaves, then runs the full e2e flow.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --base-deployment)
      BASE_DEPLOYMENT="${2:-}"; shift 2 ;;
    --deployment-file)
      DEPLOYMENT_FILE="${2:-}"; shift 2 ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${BASE_DEPLOYMENT}" ]]; then
  echo "--base-deployment is required" >&2
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
need_cmd openssl
need_cmd go
need_cmd cargo
need_cmd solana
need_cmd solana-keygen
need_cmd docker

NITRO_CLI="nitro-cli"
if [[ -x "/opt/nitro-cli/usr/bin/nitro-cli" ]]; then
  NITRO_CLI="/opt/nitro-cli/usr/bin/nitro-cli"
fi
if [[ ! -x "${NITRO_CLI}" ]]; then
  echo "missing required command: nitro-cli" >&2
  exit 1
fi

if [[ ! -e /dev/nitro_enclaves ]]; then
  echo "/dev/nitro_enclaves missing; Nitro Enclaves must be enabled on the host" >&2
  exit 1
fi

BASE_ENV="$(
  python3 - "${DEPLOYMENT_FILE}" "${BASE_DEPLOYMENT}" <<'PY'
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
emit("ADMIN", entry.get("admin"))
emit("FEE_BPS", entry.get("fee_bps"))
emit("FEE_COLLECTOR", entry.get("fee_collector"))
emit("CRP_PROGRAM_ID", entry.get("checkpoint_registry_program_id"))
emit("ORP_PROGRAM_ID", entry.get("operator_registry_program_id"))
emit("IEP_PROGRAM_ID", entry.get("intent_escrow_program_id"))
emit("RV_PROGRAM_ID", entry.get("receipt_verifier_program_id"))
emit("VERIFIER_ROUTER_PROGRAM_ID", entry.get("verifier_router_program_id"))
emit("VERIFIER_ROUTER", entry.get("verifier_router"))
emit("VERIFIER_ENTRY", entry.get("verifier_entry"))
emit("VERIFIER_PROGRAM_ID", entry.get("verifier_program_id"))
emit("JUNOCASH_CHAIN", entry.get("junocash_chain"))
emit("JUNOCASH_GENESIS_HASH", entry.get("junocash_genesis_hash"))
PY
)"

while IFS='=' read -r k v; do
  export "${k}=${v}"
done <<<"${BASE_ENV}"

if [[ -z "${RPC_URL:-}" || -z "${CRP_PROGRAM_ID:-}" || -z "${ORP_PROGRAM_ID:-}" || -z "${IEP_PROGRAM_ID:-}" || -z "${RV_PROGRAM_ID:-}" ]]; then
  echo "base deployment missing required program ids (CRP/ORP/IEP/RV)" >&2
  printf '%s\n' "${BASE_ENV}" >&2
  exit 1
fi
if [[ -z "${VERIFIER_ROUTER_PROGRAM_ID:-}" || -z "${VERIFIER_PROGRAM_ID:-}" ]]; then
  echo "base deployment missing verifier router fields" >&2
  printf '%s\n' "${BASE_ENV}" >&2
  exit 1
fi
if [[ -z "${VERIFIER_ROUTER:-}" || -z "${VERIFIER_ENTRY:-}" ]]; then
  echo "base deployment missing verifier router PDAs (verifier_router/verifier_entry)" >&2
  printf '%s\n' "${BASE_ENV}" >&2
  exit 1
fi
if [[ -z "${FEE_BPS:-}" || -z "${FEE_COLLECTOR:-}" ]]; then
  echo "base deployment missing fee fields (fee_bps/fee_collector)" >&2
  printf '%s\n' "${BASE_ENV}" >&2
  exit 1
fi
if [[ -z "${JUNOCASH_CHAIN:-}" || -z "${JUNOCASH_GENESIS_HASH:-}" ]]; then
  echo "base deployment missing JunoCash chain fields (junocash_chain/junocash_genesis_hash)" >&2
  printf '%s\n' "${BASE_ENV}" >&2
  exit 1
fi

DEPLOYMENT_ID="$(openssl rand -hex 32)"
E2E_DEPLOYMENT="e2e-tee-$(date -u +%Y%m%dT%H%M%SZ)"
TMP_DEPLOYMENTS="/tmp/juno-deployments-${E2E_DEPLOYMENT}.json"

case "$(printf '%s' "${JUNOCASH_CHAIN}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n')" in
  mainnet) CHAIN_ID=1 ;;
  testnet) CHAIN_ID=2 ;;
  regtest) CHAIN_ID=3 ;;
  *) echo "unsupported junocash_chain: ${JUNOCASH_CHAIN}" >&2; exit 1 ;;
esac

echo "rpc_url=${RPC_URL}" >&2
echo "base_deployment=${BASE_DEPLOYMENT}" >&2
echo "e2e_deployment=${E2E_DEPLOYMENT}" >&2
echo "deployment_id=${DEPLOYMENT_ID}" >&2
echo "junocash_chain_id=${CHAIN_ID}" >&2

WORKDIR="${ROOT}/tmp/e2e/devnet-testnet-tee/${E2E_DEPLOYMENT}"
mkdir -p "${WORKDIR}"

cleanup() {
  sudo "${NITRO_CLI}" terminate-enclave --all >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "building go helpers..." >&2
GO_INTENTS="${WORKDIR}/juno-intents"
GO_NITRO="${WORKDIR}/nitro-operator"
(cd "${ROOT}" && go build -o "${GO_INTENTS}" ./cmd/juno-intents)
(cd "${ROOT}" && go build -o "${GO_NITRO}" ./cmd/nitro-operator)

echo "creating funded e2e keypairs..." >&2
SOLVER_KEYPAIR="${WORKDIR}/solver.json"
CREATOR_KEYPAIR="${WORKDIR}/creator.json"
solana-keygen new --no-bip39-passphrase --silent --force -o "${SOLVER_KEYPAIR}"
solana-keygen new --no-bip39-passphrase --silent --force -o "${CREATOR_KEYPAIR}"
SOLVER_PUBKEY="$(solana-keygen pubkey "${SOLVER_KEYPAIR}")"
CREATOR_PUBKEY="$(solana-keygen pubkey "${CREATOR_KEYPAIR}")"

airdrop() {
  local pubkey="$1"
  local sol="$2"
  local kp="$3"
  for i in $(seq 1 30); do
    if solana -u "${RPC_URL}" airdrop "${sol}" "${pubkey}" --keypair "${kp}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${i}"
  done
  return 1
}

transfer_sol() {
  local from_kp="$1"
  local to_pubkey="$2"
  local sol="$3"
  for i in $(seq 1 20); do
    if solana -u "${RPC_URL}" transfer --allow-unfunded-recipient -k "${from_kp}" "${to_pubkey}" "${sol}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${i}"
  done
  return 1
}

echo "funding SOL..." >&2
airdrop "${SOLVER_PUBKEY}" 3 "${SOLVER_KEYPAIR}" || {
  echo "solver airdrop failed: ${SOLVER_PUBKEY}" >&2
  exit 1
}
transfer_sol "${SOLVER_KEYPAIR}" "${CREATOR_PUBKEY}" 1 || {
  echo "creator funding transfer failed: ${CREATOR_PUBKEY}" >&2
  exit 1
}

echo "preparing nitro log dir..." >&2
sudo mkdir -p /var/log/nitro_enclaves
sudo touch /var/log/nitro_enclaves/nitro_enclaves.log
sudo chown root:root /var/log/nitro_enclaves /var/log/nitro_enclaves/nitro_enclaves.log || true
sudo chmod 755 /var/log/nitro_enclaves || true
sudo chmod 644 /var/log/nitro_enclaves/nitro_enclaves.log || true
sudo mkdir -p /run/nitro_enclaves
sudo chown root:root /run/nitro_enclaves || true
sudo chmod 775 /run/nitro_enclaves || true

echo "building EIF (e2e)..." >&2
eif_out="${WORKDIR}/build-eif.stdout.log"
eif_err="${WORKDIR}/build-eif.stderr.log"
if ! JUNO_EIF_DOCKERFILE=enclave/operator/Dockerfile.e2e \
  JUNO_EIF_OUT_DIR="${WORKDIR}/eif" \
  JUNO_EIF_OUT_EIF="${WORKDIR}/eif/operator.eif" \
  "${ROOT}/scripts/enclave/build-eif.sh" >"${eif_out}" 2>"${eif_err}"; then
  echo "EIF build failed (tailing logs)..." >&2
  tail -n 80 "${eif_out}" >&2 || true
  tail -n 80 "${eif_err}" >&2 || true
  grep -En '(^ERROR|error|failed)' "${eif_err}" | tail -n 80 >&2 || true
  exit 1
fi
grep -E '^pcr0=[0-9a-fA-F]{96}$' "${eif_err}" >&2 || true

CID1=16
CID2=17
PORT=5000

echo "starting enclaves..." >&2
sudo "${NITRO_CLI}" run-enclave --eif-path "${WORKDIR}/eif/operator.eif" --cpu-count 2 --memory 1024 --enclave-cid "${CID1}" >/dev/null
sudo "${NITRO_CLI}" run-enclave --eif-path "${WORKDIR}/eif/operator.eif" --cpu-count 2 --memory 1024 --enclave-cid "${CID2}" >/dev/null

echo "generating attestation witnesses..." >&2
w1="$(sudo -E "${GO_NITRO}" witness --enclave-cid "${CID1}" --enclave-port "${PORT}" --deployment-id "${DEPLOYMENT_ID}" --junocash-chain-id "${CHAIN_ID}" --junocash-genesis-hash "${JUNOCASH_GENESIS_HASH}")"
w2="$(sudo -E "${GO_NITRO}" witness --enclave-cid "${CID2}" --enclave-port "${PORT}" --deployment-id "${DEPLOYMENT_ID}" --junocash-chain-id "${CHAIN_ID}" --junocash-genesis-hash "${JUNOCASH_GENESIS_HASH}")"

echo "proving attestation bundles (CUDA)..." >&2
b1_raw="$(cd "${ROOT}" && cargo run --release --locked --manifest-path risc0/attestation/host/Cargo.toml --features cuda --bin prove_attestation_bundle_v1 -- --witness-hex "${w1}")"
b2_raw="$(cd "${ROOT}" && cargo run --release --locked --manifest-path risc0/attestation/host/Cargo.toml --features cuda --bin prove_attestation_bundle_v1 -- --witness-hex "${w2}")"
b1_hex="$(printf '%s\n' "${b1_raw}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1)"
b2_hex="$(printf '%s\n' "${b2_raw}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1)"
if [[ -z "${b1_hex}" || -z "${b2_hex}" ]]; then
  echo "failed to extract attestation bundle hex" >&2
  exit 1
fi

info1="$("${GO_INTENTS}" orp-attestation-info --bundle-hex "${b1_hex}")"
info2="$("${GO_INTENTS}" orp-attestation-info --bundle-hex "${b2_hex}")"
op1="$(printf '%s\n' "${info1}" | sed -nE 's/^operator_pubkey=([1-9A-HJ-NP-Za-km-z]{32,44})$/\\1/p' | head -n 1)"
op2="$(printf '%s\n' "${info2}" | sed -nE 's/^operator_pubkey=([1-9A-HJ-NP-Za-km-z]{32,44})$/\\1/p' | head -n 1)"
meas1="$(printf '%s\n' "${info1}" | sed -nE 's/^measurement=([0-9a-fA-F]{64})$/\\1/p' | head -n 1)"
meas2="$(printf '%s\n' "${info2}" | sed -nE 's/^measurement=([0-9a-fA-F]{64})$/\\1/p' | head -n 1)"
if [[ -z "${op1}" || -z "${op2}" || -z "${meas1}" || -z "${meas2}" ]]; then
  echo "failed to parse attestation bundle info" >&2
  exit 1
fi
if [[ "${meas1}" != "${meas2}" ]]; then
  echo "enclave measurements mismatch: ${meas1} != ${meas2}" >&2
  exit 1
fi

echo "initializing ORP + registering operators..." >&2
SOLANA_RPC_URL="${RPC_URL}" "${GO_INTENTS}" init-orp \
  --orp-program-id "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID}" \
  --admin "${SOLVER_PUBKEY}" \
  --junocash-chain-id "${CHAIN_ID}" \
  --junocash-genesis-hash "${JUNOCASH_GENESIS_HASH}" \
  --verifier-router-program "${VERIFIER_ROUTER_PROGRAM_ID}" \
  --verifier-program-id "${VERIFIER_PROGRAM_ID}" \
  --allowed-measurement "${meas1}" \
  --payer-keypair "${SOLVER_KEYPAIR}" >/dev/null

SOLANA_RPC_URL="${RPC_URL}" "${GO_INTENTS}" orp-register-operator \
  --orp-program-id "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID}" \
  --bundle-hex "${b1_hex}" \
  --payer-keypair "${SOLVER_KEYPAIR}" >/dev/null

SOLANA_RPC_URL="${RPC_URL}" "${GO_INTENTS}" orp-register-operator \
  --orp-program-id "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID}" \
  --bundle-hex "${b2_hex}" \
  --payer-keypair "${SOLVER_KEYPAIR}" >/dev/null

echo "initializing CRP v2 + IEP..." >&2
crp_log="$(SOLANA_RPC_URL="${RPC_URL}" "${GO_INTENTS}" init-crp \
  --crp-program-id "${CRP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID}" \
  --admin "${ADMIN}" \
  --threshold 2 \
  --conflict-threshold 2 \
  --finalization-delay-slots 0 \
  --operator-registry-program "${ORP_PROGRAM_ID}" \
  --operator "${op1}" \
  --operator "${op2}" \
  --payer-keypair "${SOLVER_KEYPAIR}" 2>&1)" || {
  printf '%s\n' "${crp_log}" >&2
  exit 1
}
crp_config="$(printf '%s\n' "${crp_log}" | sed -nE 's/^crp_config=([1-9A-HJ-NP-Za-km-z]{32,44})$/\\1/p' | tail -n 1)"
if [[ -z "${crp_config}" ]]; then
  echo "failed to parse crp_config" >&2
  printf '%s\n' "${crp_log}" >&2
  exit 1
fi

iep_log="$(SOLANA_RPC_URL="${RPC_URL}" "${GO_INTENTS}" init-iep \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID}" \
  --fee-bps "${FEE_BPS}" \
  --fee-collector "${FEE_COLLECTOR}" \
  --checkpoint-registry-program "${CRP_PROGRAM_ID}" \
  --receipt-verifier-program "${RV_PROGRAM_ID}" \
  --verifier-router-program "${VERIFIER_ROUTER_PROGRAM_ID}" \
  --verifier-router "${VERIFIER_ROUTER}" \
  --verifier-entry "${VERIFIER_ENTRY}" \
  --verifier-program "${VERIFIER_PROGRAM_ID}" \
  --payer-keypair "${SOLVER_KEYPAIR}" 2>&1)" || {
  printf '%s\n' "${iep_log}" >&2
  exit 1
}
iep_config="$(printf '%s\n' "${iep_log}" | sed -nE 's/^iep_config=([1-9A-HJ-NP-Za-km-z]{32,44})$/\\1/p' | tail -n 1)"
if [[ -z "${iep_config}" ]]; then
  echo "failed to parse iep_config" >&2
  printf '%s\n' "${iep_log}" >&2
  exit 1
fi

python3 - <<PY
import json,time
entry = {
  "name": "${E2E_DEPLOYMENT}",
  "cluster": "devnet",
  "rpc_url": "${RPC_URL}",
  "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "deployment_id": "${DEPLOYMENT_ID}",
  "junocash_chain": "${JUNOCASH_CHAIN}",
  "junocash_genesis_hash": "${JUNOCASH_GENESIS_HASH}",
  "admin": "${ADMIN}",
  "checkpoint_registry_program_id": "${CRP_PROGRAM_ID}",
  "operator_registry_program_id": "${ORP_PROGRAM_ID}",
  "intent_escrow_program_id": "${IEP_PROGRAM_ID}",
  "receipt_verifier_program_id": "${RV_PROGRAM_ID}",
  "crp_config": "${crp_config}",
  "iep_config": "${iep_config}",
  "fee_bps": int("${FEE_BPS}"),
  "fee_collector": "${FEE_COLLECTOR}",
  "verifier_router_program_id": "${VERIFIER_ROUTER_PROGRAM_ID}",
  "verifier_router": "${VERIFIER_ROUTER}",
  "verifier_entry": "${VERIFIER_ENTRY}",
  "verifier_program_id": "${VERIFIER_PROGRAM_ID}",
  "crp_threshold": 2,
  "crp_conflict_threshold": 2,
  "crp_finalization_delay_slots": 0,
  "crp_operators": ["${op1}","${op2}"],
  "upgrade_mode": "final",
}
out = {"deployments": [entry]}
with open("${TMP_DEPLOYMENTS}", "w", encoding="utf-8") as f:
  json.dump(out, f, indent=2, sort_keys=True)
  f.write("\\n")
PY

export JUNO_E2E_SOLVER_KEYPAIR="${SOLVER_KEYPAIR}"
export JUNO_E2E_CREATOR_KEYPAIR="${CREATOR_KEYPAIR}"
export JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1="${CID1}"
export JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID2="${CID2}"
export JUNO_E2E_CRP_SUBMIT_ENCLAVE_PORT="${PORT}"
export JUNO_E2E_PRIORITY_LEVEL="${PRIORITY_LEVEL}"

echo "running full e2e..." >&2
"${ROOT}/scripts/e2e/devnet-testnet.sh" --deployment "${E2E_DEPLOYMENT}" --deployment-file "${TMP_DEPLOYMENTS}"
