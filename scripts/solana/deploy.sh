#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

CLUSTER=""
RPC_URL="${SOLANA_RPC_URL:-}"
ADMIN_PUBKEY=""
REFUND_PUBKEY=""
DEPLOYMENT_ID_HEX=""
NAME=""

FEE_BPS="25"
FEE_COLLECTOR_PUBKEY=""

CRP_THRESHOLD="2"
CRP_CONFLICT_THRESHOLD="2"
CRP_FINALIZATION_DELAY_SLOTS="0"
CRP_OPERATORS=()

SKIP_BUILD="false"
PUSH="false"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/solana/deploy.sh \
    --cluster devnet|mainnet|localnet \
    --admin <pubkey> \
    --fee-collector <pubkey> \
    --operator <pubkey> --operator <pubkey> \
    [--deployment-id <hex32>] \
    [--rpc-url <url>] \
    [--fee-bps <u16>] \
    [--threshold <u8>] [--conflict-threshold <u8>] [--finalization-delay-slots <u64>] \
    [--refund-to <pubkey>] \
    [--name <string>] \
    [--skip-build] \
    [--push]

Notes:
  - Creates a fresh disposable payer keypair under tmp/ and deletes it on success.
  - Uses Solana CLI for build+deploy; uses Go tooling for program initialization.
  - Records deployment outputs into deployments.json (tracked). You should review before pushing.
  - Programs are ALWAYS deployed immutable (upgrade authority set to --final).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --cluster)
      CLUSTER="${2:-}"; shift 2 ;;
    --rpc-url)
      RPC_URL="${2:-}"; shift 2 ;;
    --deployment-id)
      DEPLOYMENT_ID_HEX="${2:-}"; shift 2 ;;
    --name)
      NAME="${2:-}"; shift 2 ;;
    --admin)
      ADMIN_PUBKEY="${2:-}"; shift 2 ;;
    --refund-to)
      REFUND_PUBKEY="${2:-}"; shift 2 ;;
    --fee-bps)
      FEE_BPS="${2:-}"; shift 2 ;;
    --fee-collector)
      FEE_COLLECTOR_PUBKEY="${2:-}"; shift 2 ;;
    --operator)
      CRP_OPERATORS+=("${2:-}"); shift 2 ;;
    --threshold)
      CRP_THRESHOLD="${2:-}"; shift 2 ;;
    --conflict-threshold)
      CRP_CONFLICT_THRESHOLD="${2:-}"; shift 2 ;;
    --finalization-delay-slots)
      CRP_FINALIZATION_DELAY_SLOTS="${2:-}"; shift 2 ;;
    --skip-build)
      SKIP_BUILD="true"; shift 1 ;;
    --push)
      PUSH="true"; shift 1 ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${CLUSTER}" ]]; then
  echo "--cluster is required" >&2
  exit 2
fi
if [[ -z "${RPC_URL}" ]]; then
  case "${CLUSTER}" in
    devnet) RPC_URL="https://api.devnet.solana.com" ;;
    mainnet) RPC_URL="https://api.mainnet-beta.solana.com" ;;
    localnet) RPC_URL="http://127.0.0.1:8899" ;;
    *)
      echo "unknown cluster: ${CLUSTER}" >&2
      exit 2
      ;;
  esac
fi
if [[ -z "${ADMIN_PUBKEY}" ]]; then
  echo "--admin is required" >&2
  exit 2
fi
if [[ -z "${REFUND_PUBKEY}" ]]; then
  REFUND_PUBKEY="${ADMIN_PUBKEY}"
fi
if [[ -z "${FEE_COLLECTOR_PUBKEY}" ]]; then
  echo "--fee-collector is required" >&2
  exit 2
fi
if [[ "${#CRP_OPERATORS[@]}" -lt 2 ]]; then
  echo "need at least two --operator pubkeys (CRP conflict threshold requires >=2 operators)" >&2
  exit 2
fi

if [[ -z "${DEPLOYMENT_ID_HEX}" ]]; then
  if command -v openssl >/dev/null; then
    DEPLOYMENT_ID_HEX="$(openssl rand -hex 32)"
  else
    echo "openssl is required to generate --deployment-id (or pass it explicitly)" >&2
    exit 2
  fi
fi
DEPLOYMENT_ID_HEX="${DEPLOYMENT_ID_HEX#0x}"
if [[ "${#DEPLOYMENT_ID_HEX}" -ne 64 ]]; then
  echo "--deployment-id must be 32-byte hex (64 chars)" >&2
  exit 2
fi

if ! command -v solana >/dev/null; then
  echo "solana CLI not found in PATH" >&2
  exit 1
fi
if ! command -v solana-keygen >/dev/null; then
  echo "solana-keygen not found in PATH" >&2
  exit 1
fi
if ! command -v git >/dev/null; then
  echo "git not found in PATH" >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  echo "python3 not found in PATH" >&2
  exit 1
fi
if [[ "${SKIP_BUILD}" != "true" ]] && ! command -v cargo >/dev/null; then
  echo "cargo not found in PATH (required unless --skip-build)" >&2
  exit 1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="${ROOT}/tmp/solana/deploy/${ts}"
mkdir -p "${WORKDIR}"

PAYER_KEYPAIR="${WORKDIR}/payer.json"
CRP_KEYPAIR="${WORKDIR}/crp-program.json"
IEP_KEYPAIR="${WORKDIR}/iep-program.json"
RV_KEYPAIR="${WORKDIR}/receipt-verifier-program.json"

cleanup() {
  rm -rf "${WORKDIR}" >/dev/null 2>&1 || true
}

on_exit() {
  status=$?
  if [[ "${status}" -ne 0 ]]; then
    echo "deploy failed; NOT deleting ${WORKDIR} (payer key may be funded). Clean up manually after refunding." >&2
    exit "${status}"
  fi
  cleanup
}
trap on_exit EXIT

echo "workdir: ${WORKDIR}" >&2
solana-keygen new --no-bip39-passphrase --silent --force -o "${PAYER_KEYPAIR}"
PAYER_PUBKEY="$(solana-keygen pubkey "${PAYER_KEYPAIR}")"
echo "payer: ${PAYER_PUBKEY}" >&2

solana-keygen new --no-bip39-passphrase --silent --force -o "${CRP_KEYPAIR}"
solana-keygen new --no-bip39-passphrase --silent --force -o "${IEP_KEYPAIR}"
solana-keygen new --no-bip39-passphrase --silent --force -o "${RV_KEYPAIR}"
CRP_PROGRAM_ID="$(solana-keygen pubkey "${CRP_KEYPAIR}")"
IEP_PROGRAM_ID="$(solana-keygen pubkey "${IEP_KEYPAIR}")"
RV_PROGRAM_ID="$(solana-keygen pubkey "${RV_KEYPAIR}")"

echo "deployment_id: ${DEPLOYMENT_ID_HEX}" >&2
echo "crp_program_id: ${CRP_PROGRAM_ID}" >&2
echo "iep_program_id: ${IEP_PROGRAM_ID}" >&2
echo "receipt_verifier_program_id: ${RV_PROGRAM_ID}" >&2

if [[ "${SKIP_BUILD}" != "true" ]]; then
  echo "building Solana programs (SBF, release)..." >&2
  # cargo-build-sbf treats cargo flags (like --release) as passthrough args after "--".
  (cd "${ROOT}" && cargo build-sbf --manifest-path solana/Cargo.toml -- --release)
fi

CRP_SO="${ROOT}/solana/target/deploy/juno_intents_checkpoint_registry.so"
IEP_SO="${ROOT}/solana/target/deploy/juno_intents_intent_escrow.so"
RV_SO="${ROOT}/solana/target/deploy/juno_intents_receipt_verifier.so"

for f in "${CRP_SO}" "${IEP_SO}" "${RV_SO}"; do
  if [[ ! -f "${f}" ]]; then
    echo "missing program artifact: ${f}" >&2
    exit 1
  fi
done

echo "estimating required SOL..." >&2
crp_bytes="$(wc -c <"${CRP_SO}" | tr -d ' ')"
iep_bytes="$(wc -c <"${IEP_SO}" | tr -d ' ')"
rv_bytes="$(wc -c <"${RV_SO}" | tr -d ' ')"

estimate_rent_exempt() {
  local bytes="$1"
  local out
  out="$(solana -u "${RPC_URL}" rent "${bytes}" 2>/dev/null || true)"
  # Expected line: "Rent-exempt minimum: <lamports> lamports"
  echo "${out}" | awk '/Rent-exempt minimum:/ {print $3; exit}' || true
}

rent_crp="$(estimate_rent_exempt "$((crp_bytes + 2048))")"
rent_iep="$(estimate_rent_exempt "$((iep_bytes + 2048))")"
rent_rv="$(estimate_rent_exempt "$((rv_bytes + 2048))")"

need_lamports="0"
if [[ -n "${rent_crp}" && -n "${rent_iep}" && -n "${rent_rv}" ]]; then
  # Conservative estimate: 3x rent per program (buffer + programdata + slack) + 0.2 SOL fees.
  need_lamports="$(( (3 * rent_crp) + (3 * rent_iep) + (3 * rent_rv) + 200000000 ))"
else
  # Fallback if 'solana rent' output parsing fails.
  need_lamports="$(( 5 * 1000000000 ))"
  echo "warning: could not parse solana rent output; using conservative default: 5 SOL" >&2
fi

need_sol="$(python3 -c 'import sys; need=int(sys.argv[1]); print(f"{need/1e9:.4f}")' "${need_lamports}")"
echo "estimated required balance: ~${need_sol} SOL (${need_lamports} lamports)" >&2

get_balance_lamports() {
  local out
  out="$(solana -u "${RPC_URL}" balance "${PAYER_PUBKEY}" --lamports 2>/dev/null || true)"
  echo "${out}" | awk '{print $1; exit}' || true
}

airdrop_if_possible() {
  if [[ "${CLUSTER}" != "devnet" && "${CLUSTER}" != "localnet" ]]; then
    return 0
  fi
  for _ in $(seq 1 10); do
    bal="$(get_balance_lamports)"
    if [[ -n "${bal}" && "${bal}" -ge "${need_lamports}" ]]; then
      return 0
    fi
    echo "airdropping 2 SOL..." >&2
    solana -u "${RPC_URL}" airdrop 2 "${PAYER_PUBKEY}" --keypair "${PAYER_KEYPAIR}" >/dev/null 2>&1 || true
    sleep 2
  done
}

airdrop_if_possible || true

echo "waiting for payer to be funded (send >= ${need_sol} SOL to ${PAYER_PUBKEY})..." >&2
for _ in $(seq 1 240); do
  bal="$(get_balance_lamports)"
  if [[ -n "${bal}" && "${bal}" -ge "${need_lamports}" ]]; then
    echo "payer funded: ${bal} lamports" >&2
    break
  fi
  sleep 5
done
bal="$(get_balance_lamports)"
if [[ -z "${bal}" || "${bal}" -lt "${need_lamports}" ]]; then
  echo "payer still underfunded (balance=${bal:-unknown} lamports)" >&2
  exit 1
fi

echo "deploying CRP..." >&2
solana -u "${RPC_URL}" program deploy "${CRP_SO}" \
  --keypair "${PAYER_KEYPAIR}" \
  --program-id "${CRP_KEYPAIR}" \
  --upgrade-authority "${PAYER_KEYPAIR}"

echo "deploying IEP..." >&2
solana -u "${RPC_URL}" program deploy "${IEP_SO}" \
  --keypair "${PAYER_KEYPAIR}" \
  --program-id "${IEP_KEYPAIR}" \
  --upgrade-authority "${PAYER_KEYPAIR}"

echo "deploying receipt-verifier..." >&2
solana -u "${RPC_URL}" program deploy "${RV_SO}" \
  --keypair "${PAYER_KEYPAIR}" \
  --program-id "${RV_KEYPAIR}" \
  --upgrade-authority "${PAYER_KEYPAIR}"

echo "finalizing program upgrade authorities (immutable)..." >&2
solana -u "${RPC_URL}" program set-upgrade-authority "${CRP_PROGRAM_ID}" --final --keypair "${PAYER_KEYPAIR}"
solana -u "${RPC_URL}" program set-upgrade-authority "${IEP_PROGRAM_ID}" --final --keypair "${PAYER_KEYPAIR}"
solana -u "${RPC_URL}" program set-upgrade-authority "${RV_PROGRAM_ID}" --final --keypair "${PAYER_KEYPAIR}"

echo "initializing CRP config..." >&2
INIT_CRP_ARGS=(
  --crp-program-id "${CRP_PROGRAM_ID}"
  --deployment-id "${DEPLOYMENT_ID_HEX}"
  --admin "${ADMIN_PUBKEY}"
  --threshold "${CRP_THRESHOLD}"
  --conflict-threshold "${CRP_CONFLICT_THRESHOLD}"
  --finalization-delay-slots "${CRP_FINALIZATION_DELAY_SLOTS}"
  --payer-keypair "${PAYER_KEYPAIR}"
)
for op in "${CRP_OPERATORS[@]}"; do
  INIT_CRP_ARGS+=(--operator "${op}")
done
SOLANA_RPC_URL="${RPC_URL}" go run ./cmd/juno-intents init-crp "${INIT_CRP_ARGS[@]}" >/dev/null

echo "initializing IEP config..." >&2
SOLANA_RPC_URL="${RPC_URL}" go run ./cmd/juno-intents init-iep \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fee-bps "${FEE_BPS}" \
  --fee-collector "${FEE_COLLECTOR_PUBKEY}" \
  --checkpoint-registry-program "${CRP_PROGRAM_ID}" \
  --receipt-verifier-program "${RV_PROGRAM_ID}" \
  --payer-keypair "${PAYER_KEYPAIR}" >/dev/null

CRP_CONFIG_PDA="$(go run ./cmd/juno-intents pda --program-id "${CRP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --print config)"
IEP_CONFIG_PDA="$(go run ./cmd/juno-intents pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --print config)"

if [[ -z "${NAME}" ]]; then
  NAME="${CLUSTER}-${ts}"
fi

echo "recording deployment into deployments.json..." >&2
export DEPLOY_RECORD_ROOT="${ROOT}"
export DEPLOY_RECORD_NAME="${NAME}"
export DEPLOY_RECORD_CLUSTER="${CLUSTER}"
export DEPLOY_RECORD_RPC_URL="${RPC_URL}"
export DEPLOY_RECORD_DEPLOYMENT_ID="${DEPLOYMENT_ID_HEX}"
export DEPLOY_RECORD_ADMIN="${ADMIN_PUBKEY}"
export DEPLOY_RECORD_CRP_PROGRAM_ID="${CRP_PROGRAM_ID}"
export DEPLOY_RECORD_IEP_PROGRAM_ID="${IEP_PROGRAM_ID}"
export DEPLOY_RECORD_RV_PROGRAM_ID="${RV_PROGRAM_ID}"
export DEPLOY_RECORD_CRP_CONFIG="${CRP_CONFIG_PDA}"
export DEPLOY_RECORD_IEP_CONFIG="${IEP_CONFIG_PDA}"
export DEPLOY_RECORD_FEE_BPS="${FEE_BPS}"
export DEPLOY_RECORD_FEE_COLLECTOR="${FEE_COLLECTOR_PUBKEY}"
export DEPLOY_RECORD_CRP_THRESHOLD="${CRP_THRESHOLD}"
export DEPLOY_RECORD_CRP_CONFLICT_THRESHOLD="${CRP_CONFLICT_THRESHOLD}"
export DEPLOY_RECORD_CRP_DELAY_SLOTS="${CRP_FINALIZATION_DELAY_SLOTS}"
export DEPLOY_RECORD_CRP_OPERATORS_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${CRP_OPERATORS[@]}")"

python3 - <<'PY'
import json
import os
import subprocess
import time

root = os.environ["DEPLOY_RECORD_ROOT"]
path = os.path.join(root, "deployments.json")

with open(path, "r", encoding="utf-8") as f:
    reg = json.load(f)

entry = {
    "name": os.environ["DEPLOY_RECORD_NAME"],
    "cluster": os.environ["DEPLOY_RECORD_CLUSTER"],
    "rpc_url": os.environ["DEPLOY_RECORD_RPC_URL"],
    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "deployment_id": os.environ["DEPLOY_RECORD_DEPLOYMENT_ID"],
    "admin": os.environ["DEPLOY_RECORD_ADMIN"],
    "checkpoint_registry_program_id": os.environ["DEPLOY_RECORD_CRP_PROGRAM_ID"],
    "intent_escrow_program_id": os.environ["DEPLOY_RECORD_IEP_PROGRAM_ID"],
    "receipt_verifier_program_id": os.environ["DEPLOY_RECORD_RV_PROGRAM_ID"],
    "crp_config": os.environ["DEPLOY_RECORD_CRP_CONFIG"],
    "iep_config": os.environ["DEPLOY_RECORD_IEP_CONFIG"],
    "fee_bps": int(os.environ["DEPLOY_RECORD_FEE_BPS"]),
    "fee_collector": os.environ["DEPLOY_RECORD_FEE_COLLECTOR"],
    "crp_threshold": int(os.environ["DEPLOY_RECORD_CRP_THRESHOLD"]),
    "crp_conflict_threshold": int(os.environ["DEPLOY_RECORD_CRP_CONFLICT_THRESHOLD"]),
    "crp_finalization_delay_slots": int(os.environ["DEPLOY_RECORD_CRP_DELAY_SLOTS"]),
    "crp_operators": json.loads(os.environ["DEPLOY_RECORD_CRP_OPERATORS_JSON"]),
    "upgrade_mode": "final",
}

reg.setdefault("deployments", [])
reg["deployments"].append(entry)

with open(path, "w", encoding="utf-8") as f:
    json.dump(reg, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "committing deployments.json..." >&2
(cd "${ROOT}" && git add deployments.json && git commit -m "chore(deploy): record ${NAME}" )
if [[ "${PUSH}" == "true" ]]; then
  (cd "${ROOT}" && git push origin main)
fi

echo "refunding remaining balance to ${REFUND_PUBKEY} (best-effort)..." >&2
solana -u "${RPC_URL}" transfer "${REFUND_PUBKEY}" ALL --keypair "${PAYER_KEYPAIR}" >/dev/null 2>&1 || true
echo "done" >&2
