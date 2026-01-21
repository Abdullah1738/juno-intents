#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENT_FILE="deployments.json"
DEPLOYMENT_NAME=""

NET_AMOUNT_A="${JUNO_E2E_NET_AMOUNT_A:-1000}"
NET_AMOUNT_B="${JUNO_E2E_NET_AMOUNT_B:-1000}"
JUNOCASH_SEND_AMOUNT_A="${JUNO_E2E_JUNOCASH_SEND_AMOUNT_A:-1.0}"
JUNOCASH_SEND_AMOUNT_B="${JUNO_E2E_JUNOCASH_SEND_AMOUNT_B:-0.5}"
JUNOCASH_SEND_MINCONF="${JUNO_E2E_JUNOCASH_SEND_MINCONF:-}"
JUNOCASH_SHIELD_LIMIT="${JUNO_E2E_JUNOCASH_SHIELD_LIMIT:-10}"
JUNOCASH_TESTNET_WALLET_DAT_GZ_B64="${JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64:-}"
JUNOCASH_TESTNET_PREFUND_WIF="${JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF:-}"
JUNOCASH_TESTNET_PREFUND_AMOUNT="${JUNO_E2E_JUNOCASH_TESTNET_PREFUND_AMOUNT:-5.0}"

PRIORITY_LEVEL="${JUNO_E2E_PRIORITY_LEVEL:-Medium}"

E2E_ARTIFACT_DIR="${JUNO_E2E_ARTIFACT_DIR:-}"

SOLVER_KEYPAIR_OVERRIDE="${JUNO_E2E_SOLVER_KEYPAIR:-}"
SOLVER2_KEYPAIR_OVERRIDE="${JUNO_E2E_SOLVER2_KEYPAIR:-}"
CREATOR_KEYPAIR_OVERRIDE="${JUNO_E2E_CREATOR_KEYPAIR:-}"

CRP_OPERATOR1_KEYPAIR="${JUNO_E2E_CRP_OPERATOR1_KEYPAIR:-}"
CRP_OPERATOR2_KEYPAIR="${JUNO_E2E_CRP_OPERATOR2_KEYPAIR:-}"

CRP_SUBMIT_ENCLAVE_CID1="${JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1:-}"
CRP_SUBMIT_ENCLAVE_CID2="${JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID2:-}"
CRP_SUBMIT_ENCLAVE_PORT="${JUNO_E2E_CRP_SUBMIT_ENCLAVE_PORT:-5000}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/e2e/devnet-testnet.sh --deployment <name> [--deployment-file <path>]

Environment (optional):
  JUNO_E2E_NET_AMOUNT_A            (default: 1000)
  JUNO_E2E_NET_AMOUNT_B            (default: 1000)
  JUNO_E2E_JUNOCASH_SEND_AMOUNT_A  (default: 1.0)
  JUNO_E2E_JUNOCASH_SEND_AMOUNT_B  (default: 0.5)
  JUNO_E2E_JUNOCASH_SEND_MINCONF   (default: regtest=1, testnet=10)
  JUNO_E2E_JUNOCASH_SHIELD_LIMIT   (default: 10)
  JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64 (optional: base64(gzip(wallet.dat)) for a prefunded testnet wallet; required for shielded-only funding)
  JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF (optional: prefunded testnet transparent address private key in WIF format)
  JUNO_E2E_JUNOCASH_TESTNET_PREFUND_AMOUNT (default: 5.0; amount to fund the user orchard UA from ANY_TADDR)
  JUNO_E2E_PRIORITY_LEVEL          (default: Medium)
  JUNO_E2E_SOLVER_KEYPAIR          (optional: funded Solana CLI JSON keypair path; skips airdrop)
  JUNO_E2E_SOLVER2_KEYPAIR         (optional: funded Solana CLI JSON keypair path for second solver)
  JUNO_E2E_CREATOR_KEYPAIR         (optional: funded Solana CLI JSON keypair path; skips airdrop)
  JUNO_E2E_CRP_OPERATOR1_KEYPAIR   (optional: Solana CLI JSON keypair path for CRP operator #1)
  JUNO_E2E_CRP_OPERATOR2_KEYPAIR   (optional: Solana CLI JSON keypair path for CRP operator #2)
  JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1 (optional: if set with CID2, uses Nitro enclaves to sign SubmitObservation)
  JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID2 (optional: if set with CID1, uses Nitro enclaves to sign SubmitObservation)
  JUNO_E2E_CRP_SUBMIT_ENCLAVE_PORT (default: 5000)

Notes:
  - For testnet deployments, the JunoCash Docker harness connects to public testnet.
  - For reliable CI, prefer JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64 and fund the wallet’s UA once.
    As a fallback, JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF can fund the user UA from ANY_TADDR.
  - Runs both IEP directions (A and B) against the selected Solana devnet deployment.
  - Generates *real* zkVM->Groth16 receipt bundles (CUDA) and settles on Solana.
  - Uses CRP operator run-mode to finalize the Orchard roots (chain type + genesis verified).
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
need_cmd docker
need_cmd solana
need_cmd solana-keygen
need_cmd spl-token
need_cmd cargo
need_cmd go
need_cmd curl

redact_url() {
  printf '%s' "$1" | sed -E 's/(api-key=)[^&]+/\1***/g'
}

if [[ -n "${SOLVER_KEYPAIR_OVERRIDE}" && ! -f "${SOLVER_KEYPAIR_OVERRIDE}" ]]; then
  echo "solver keypair not found: ${SOLVER_KEYPAIR_OVERRIDE}" >&2
  exit 2
fi
if [[ -n "${SOLVER2_KEYPAIR_OVERRIDE}" && ! -f "${SOLVER2_KEYPAIR_OVERRIDE}" ]]; then
  echo "solver2 keypair not found: ${SOLVER2_KEYPAIR_OVERRIDE}" >&2
  exit 2
fi
if [[ -n "${CREATOR_KEYPAIR_OVERRIDE}" && ! -f "${CREATOR_KEYPAIR_OVERRIDE}" ]]; then
  echo "creator keypair not found: ${CREATOR_KEYPAIR_OVERRIDE}" >&2
  exit 2
fi
if [[ -n "${CRP_OPERATOR1_KEYPAIR}" && ! -f "${CRP_OPERATOR1_KEYPAIR}" ]]; then
  echo "CRP operator #1 keypair not found: ${CRP_OPERATOR1_KEYPAIR}" >&2
  exit 2
fi
if [[ -n "${CRP_OPERATOR2_KEYPAIR}" && ! -f "${CRP_OPERATOR2_KEYPAIR}" ]]; then
  echo "CRP operator #2 keypair not found: ${CRP_OPERATOR2_KEYPAIR}" >&2
  exit 2
fi
if [[ -n "${CRP_SUBMIT_ENCLAVE_CID1}" || -n "${CRP_SUBMIT_ENCLAVE_CID2}" ]]; then
  if [[ -z "${CRP_SUBMIT_ENCLAVE_CID1}" || -z "${CRP_SUBMIT_ENCLAVE_CID2}" ]]; then
    echo "both JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1 and JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID2 are required when using enclaves" >&2
    exit 2
  fi
  if [[ ! "${CRP_SUBMIT_ENCLAVE_CID1}" =~ ^[0-9]+$ || ! "${CRP_SUBMIT_ENCLAVE_CID2}" =~ ^[0-9]+$ ]]; then
    echo "enclave CIDs must be u32 integers" >&2
    exit 2
  fi
  if [[ ! "${CRP_SUBMIT_ENCLAVE_PORT}" =~ ^[0-9]+$ || "${CRP_SUBMIT_ENCLAVE_PORT}" -le 0 || "${CRP_SUBMIT_ENCLAVE_PORT}" -gt 4294967295 ]]; then
    echo "enclave port must be a u32 integer > 0" >&2
    exit 2
  fi
fi

airdrop() {
  local pubkey="$1"
  local sol="$2"
  local kp="$3"
  for _ in $(seq 1 10); do
    if solana -u "${SOLANA_RPC_URL}" airdrop "${sol}" "${pubkey}" --keypair "${kp}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "airdrop failed for ${pubkey}" >&2
  return 1
}

wait_for_account() {
  local pubkey="$1"
  local attempts="${2:-60}"
  for _ in $(seq 1 "${attempts}"); do
    if solana -u "${SOLANA_RPC_URL}" account "${pubkey}" --output json-compact >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "account not found after waiting: ${pubkey}" >&2
  return 1
}

confirm_sig() {
  local sig="$1"
  local attempts="${2:-30}"
  for _ in $(seq 1 "${attempts}"); do
    out="$(solana -u "${SOLANA_RPC_URL}" confirm "${sig}" --output json-compact 2>/dev/null)" && {
      if python3 - "${out}" <<'PY'
import json,sys
raw=sys.argv[1]
d=json.loads(raw)
err=d.get("err")
if err not in (None, "null", {}):
  raise SystemExit(1)
PY
      then
        return 0
      fi
      echo "transaction failed: ${sig}" >&2
      printf '%s\n' "${out}" >&2
      return 1
    }
    sleep 2
  done
  echo "failed to confirm signature: ${sig}" >&2
  return 1
}

solana_balance_lamports() {
  local pubkey="$1"
  local raw
  raw="$(solana -u "${SOLANA_RPC_URL}" balance "${pubkey}" --lamports 2>/dev/null || true)"
  python3 -c 'import re,sys
raw=sys.stdin.read()
m=re.search(r"(\\d+)", raw)
print(m.group(1) if m else "")
' <<<"${raw}"
}

parse_spl_address() {
  python3 -c 'import json,re,sys
raw=sys.stdin.read().strip()
if not raw:
  raise SystemExit("empty spl-token output")
try:
  data=json.loads(raw)
  addr=((data.get("commandOutput") or {}).get("address") or "").strip()
  if addr:
    print(addr); raise SystemExit(0)
except Exception:
  pass
m=re.search(r"[1-9A-HJ-NP-Za-km-z]{32,44}", raw)
if not m:
  raise SystemExit("no base58 pubkey in output")
print(m.group(0))'
}

parse_spl_signature() {
  python3 -c 'import json,re,sys
raw=sys.stdin.read().strip()
if not raw:
  raise SystemExit("empty spl-token output")
try:
  data=json.loads(raw)
  sig=(((((data.get("commandOutput") or {}).get("transactionData") or {}).get("signature")) or "").strip())
  if sig:
    print(sig); raise SystemExit(0)
except Exception:
  pass
m=re.search(r"[1-9A-HJ-NP-Za-km-z]{80,100}", raw)
if not m:
  raise SystemExit("no signature in output")
print(m.group(0))'
}

ata_for() {
  local owner="$1"
  local mint="$2"
  if ! out="$(spl-token -u "${SOLANA_RPC_URL}" address --token "${mint}" --owner "${owner}" --verbose --output json-compact 2>&1)"; then
    printf '%s\n' "${out}" >&2
    return 1
  fi
  python3 -c 'import json,re,sys
raw=sys.stdin.read().strip()
try:
  d=json.loads(raw)
  for k in ("associatedTokenAddress","associated_token_address","address"):
    v=(d.get(k) or "").strip()
    if v:
      print(v); raise SystemExit(0)
except Exception:
  pass
m=re.search(r"[1-9A-HJ-NP-Za-km-z]{32,44}", raw)
if not m:
  raise SystemExit("no base58 pubkey in output")
print(m.group(0))' <<<"${out}"
}

parse_junocash_opid() {
  python3 -c 'import json,re,sys
raw=sys.stdin.read().strip()
if not raw:
  raise SystemExit("empty output")
try:
  data=json.loads(raw)
  if isinstance(data, dict) and "opid" in data:
    print(str(data["opid"])); raise SystemExit(0)
  if isinstance(data, str) and data:
    print(data); raise SystemExit(0)
except Exception:
  pass
raw=raw.strip().strip("\"")
m=re.search(r"opid[-A-Za-z0-9]+", raw)
if m:
  print(m.group(0)); raise SystemExit(0)
print(raw)'
}

DEPLOY_INFO="$(
  python3 - "${DEPLOYMENT_FILE}" "${DEPLOYMENT_NAME}" <<'PY'
import json,sys
path=sys.argv[1]
name=sys.argv[2]
with open(path,"r",encoding="utf-8") as f:
  d=json.load(f)
for it in (d.get("deployments") or []):
  if it.get("name")==name:
    print("cluster="+str(it.get("cluster","")).strip())
    print("rpc_url="+str(it.get("rpc_url","")).strip())
    print("deployment_id="+str(it.get("deployment_id","")).strip())
    print("fee_bps="+str(it.get("fee_bps","")).strip())
    print("fee_collector="+str(it.get("fee_collector","")).strip())
    print("junocash_chain="+str(it.get("junocash_chain","")).strip())
    print("junocash_genesis_hash="+str(it.get("junocash_genesis_hash","")).strip())
    sys.exit(0)
raise SystemExit("deployment not found")
PY
)"

DEPLOY_CLUSTER="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^cluster=(.+)$/\1/p' | head -n 1)"
DEPLOY_RPC_URL="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^rpc_url=(.+)$/\1/p' | head -n 1)"
DEPLOYMENT_ID_HEX="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^deployment_id=(.+)$/\1/p' | head -n 1)"
FEE_BPS="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^fee_bps=(.+)$/\1/p' | head -n 1)"
FEE_COLLECTOR_PUBKEY="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^fee_collector=(.+)$/\1/p' | head -n 1)"
JUNOCASH_CHAIN_EXPECTED="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^junocash_chain=(.+)$/\1/p' | head -n 1)"
JUNOCASH_GENESIS_EXPECTED="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^junocash_genesis_hash=(.+)$/\1/p' | head -n 1)"

if [[ -z "${DEPLOY_RPC_URL}" || -z "${DEPLOYMENT_ID_HEX}" || -z "${FEE_BPS}" || -z "${FEE_COLLECTOR_PUBKEY}" || -z "${JUNOCASH_CHAIN_EXPECTED}" || -z "${JUNOCASH_GENESIS_EXPECTED}" ]]; then
  echo "failed to parse deployment fields" >&2
  printf '%s\n' "${DEPLOY_INFO}" >&2
  exit 1
fi
if [[ "${DEPLOY_CLUSTER}" != "devnet" ]]; then
  echo "deployment must be devnet (got cluster=${DEPLOY_CLUSTER})" >&2
  exit 2
fi

SOLANA_RPC_URL="${SOLANA_RPC_URL:-${DEPLOY_RPC_URL}}"

export SOLANA_RPC_URL

JUNOCASH_CHAIN="$(printf '%s' "${JUNOCASH_CHAIN_EXPECTED}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n')"
JUNOCASH_CLI=""
JUNOCASH_UP=""
JUNOCASH_DOWN=""
JUNOCASH_DATA_DIR=""
case "${JUNOCASH_CHAIN}" in
  regtest)
    JUNOCASH_CLI="scripts/junocash/regtest/cli.sh"
    JUNOCASH_UP="scripts/junocash/regtest/up.sh"
    JUNOCASH_DOWN="scripts/junocash/regtest/down.sh"
    JUNOCASH_DATA_DIR="${JUNO_REGTEST_DATA_DIR:-tmp/junocash-regtest}"
    ;;
  testnet)
    JUNOCASH_CLI="scripts/junocash/testnet/cli.sh"
    JUNOCASH_UP="scripts/junocash/testnet/up.sh"
    JUNOCASH_DOWN="scripts/junocash/testnet/down.sh"
    JUNOCASH_DATA_DIR="${JUNO_TESTNET_DATA_DIR_A:-tmp/junocash-testnet-a}"
    ;;
  *)
    echo "unsupported deployment junocash_chain: ${JUNOCASH_CHAIN_EXPECTED}" >&2
    exit 2
    ;;
esac

ts="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="${ROOT}/tmp/e2e/devnet-testnet/${DEPLOYMENT_NAME}/${ts}"
mkdir -p "${WORKDIR}"

if [[ "${JUNOCASH_CHAIN}" == "testnet" ]]; then
  export JUNO_TESTNET_MAXCONNECTIONS="${JUNO_TESTNET_MAXCONNECTIONS:-64}"
  export JUNO_TESTNET_DBCACHE_MB="${JUNO_TESTNET_DBCACHE_MB:-4096}"
  export JUNO_TESTNET_PAR="${JUNO_TESTNET_PAR:-0}"
fi

if [[ "${JUNOCASH_CHAIN}" == "testnet" && -n "${JUNOCASH_TESTNET_WALLET_DAT_GZ_B64}" ]]; then
  export JUNO_TESTNET_DATA_DIR_A="${WORKDIR}/junocash-testnet-a"
  JUNOCASH_DATA_DIR="${JUNO_TESTNET_DATA_DIR_A}"
  echo "seeding junocash testnet wallet.dat from JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64..." >&2
  mkdir -p "${JUNO_TESTNET_DATA_DIR_A}/testnet3"
  python3 - "${JUNO_TESTNET_DATA_DIR_A}/testnet3/wallet.dat" <<'PY'
import base64,gzip,os,sys
out=sys.argv[1]
b64=os.environ.get("JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64","")
if not b64:
  raise SystemExit(2)
payload=base64.b64decode("".join(b64.split()))
raw=gzip.decompress(payload)
with open(out,"wb") as f:
  f.write(raw)
PY
  chmod 600 "${JUNO_TESTNET_DATA_DIR_A}/testnet3/wallet.dat" || true
fi

SOLVERNET1_PID=""
SOLVERNET2_PID=""

E2E_STAGE="init"
set_stage() {
  E2E_STAGE="$1"
  echo "e2e_stage=${E2E_STAGE}" >&2
}

cleanup() {
  if [[ -n "${SOLVERNET1_PID}" ]]; then
    kill "${SOLVERNET1_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SOLVERNET2_PID}" ]]; then
    kill "${SOLVERNET2_PID}" >/dev/null 2>&1 || true
  fi
  "${JUNOCASH_DOWN}" >/dev/null 2>&1 || true
}

write_e2e_summary() {
  local exit_code="$1"
  if [[ -z "${E2E_ARTIFACT_DIR}" ]]; then
    return 0
  fi
  mkdir -p "${E2E_ARTIFACT_DIR}"

  local out="${E2E_ARTIFACT_DIR}/e2e-summary.json"
  python3 - <<PY
import json,time
summary = {
  "stage": "${E2E_STAGE}",
  "exit_code": int("${exit_code}"),
  "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "deployment": "${DEPLOYMENT_NAME}",
  "workdir": "${WORKDIR}",
  "solana": {
    "rpc_url": "${SOLANA_RPC_URL}",
    "solver_pubkey": "${SOLVER_PUBKEY:-}",
    "solver2_pubkey": "${SOLVER2_PUBKEY:-}",
    "creator_pubkey": "${CREATOR_PUBKEY:-}",
  },
  "junocash": {
    "chain": "${JUNOCASH_CHAIN}",
  },
}
with open("${out}", "w", encoding="utf-8") as f:
  json.dump(summary, f, indent=2, sort_keys=True)
  f.write("\\n")
PY

  echo "e2e_summary=${out}" >&2
  echo "e2e_summary_artifact=${E2E_ARTIFACT_DIR}/e2e-summary.json" >&2
}

on_exit() {
  local exit_code=$?
  trap - EXIT
  write_e2e_summary "${exit_code}" || true
  cleanup
  exit "${exit_code}"
}
trap on_exit EXIT

echo "workdir: ${WORKDIR}" >&2
echo "deployment: ${DEPLOYMENT_NAME}" >&2
echo "solana_rpc_url: $(redact_url "${SOLANA_RPC_URL}")" >&2
echo "junocash_chain: ${JUNOCASH_CHAIN}" >&2

if [[ -z "${JUNOCASH_SEND_MINCONF}" ]]; then
  if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
    JUNOCASH_SEND_MINCONF="1"
  else
    JUNOCASH_SEND_MINCONF="10"
  fi
fi
echo "junocash_send_minconf=${JUNOCASH_SEND_MINCONF}" >&2
echo "junocash_shield_limit=${JUNOCASH_SHIELD_LIMIT}" >&2

set_stage "start_junocash"
echo "starting JunoCash ${JUNOCASH_CHAIN} docker harness (sync begins in background)..." >&2
junocash_up_out="${WORKDIR}/junocash-up.stdout.log"
junocash_up_err="${WORKDIR}/junocash-up.stderr.log"
if ! "${JUNOCASH_UP}" >"${junocash_up_out}" 2>"${junocash_up_err}"; then
  echo "failed to start JunoCash docker harness (chain=${JUNOCASH_CHAIN})" >&2
  tail -n 200 "${junocash_up_out}" >&2 || true
  tail -n 200 "${junocash_up_err}" >&2 || true
  exit 1
fi

set_stage "build_clis"
echo "building Go CLIs..." >&2
GO_INTENTS="${WORKDIR}/juno-intents"
GO_CRP="${WORKDIR}/crp-operator"
GO_CRP_MONITOR="${WORKDIR}/crp-monitor"
GO_SOLVERNET="${WORKDIR}/solvernet"
(cd "${ROOT}" && go build -o "${GO_INTENTS}" ./cmd/juno-intents)
(cd "${ROOT}" && go build -o "${GO_CRP}" ./cmd/crp-operator)
(cd "${ROOT}" && go build -o "${GO_CRP_MONITOR}" ./cmd/crp-monitor)
(cd "${ROOT}" && go build -o "${GO_SOLVERNET}" ./cmd/solvernet)

set_stage "select_keypairs"
echo "selecting Solana keypairs..." >&2
SOLVER_KEYPAIR="${WORKDIR}/solver.json"
SOLVER2_KEYPAIR="${WORKDIR}/solver2.json"
CREATOR_KEYPAIR="${WORKDIR}/creator.json"
if [[ -n "${SOLVER_KEYPAIR_OVERRIDE}" ]]; then
  SOLVER_KEYPAIR="${SOLVER_KEYPAIR_OVERRIDE}"
else
  solana-keygen new --no-bip39-passphrase --silent --force -o "${SOLVER_KEYPAIR}"
fi
if [[ -n "${SOLVER2_KEYPAIR_OVERRIDE}" ]]; then
  SOLVER2_KEYPAIR="${SOLVER2_KEYPAIR_OVERRIDE}"
else
  solana-keygen new --no-bip39-passphrase --silent --force -o "${SOLVER2_KEYPAIR}"
fi
if [[ -n "${CREATOR_KEYPAIR_OVERRIDE}" ]]; then
  CREATOR_KEYPAIR="${CREATOR_KEYPAIR_OVERRIDE}"
else
  solana-keygen new --no-bip39-passphrase --silent --force -o "${CREATOR_KEYPAIR}"
fi
SOLVER_PUBKEY="$(solana-keygen pubkey "${SOLVER_KEYPAIR}")"
SOLVER2_PUBKEY="$(solana-keygen pubkey "${SOLVER2_KEYPAIR}")"
CREATOR_PUBKEY="$(solana-keygen pubkey "${CREATOR_KEYPAIR}")"
echo "solver_pubkey=${SOLVER_PUBKEY}" >&2
echo "solver2_pubkey=${SOLVER2_PUBKEY}" >&2
echo "creator_pubkey=${CREATOR_PUBKEY}" >&2
echo "solana_cli=$(solana --version)" >&2
echo "spl_token_cli=$(spl-token --version)" >&2
solver_balance_lamports="$(solana_balance_lamports "${SOLVER_PUBKEY}")"
echo "solver_balance_lamports=${solver_balance_lamports:-unknown}" >&2
creator_balance_lamports="$(solana_balance_lamports "${CREATOR_PUBKEY}")"
echo "creator_balance_lamports=${creator_balance_lamports:-unknown}" >&2

OP1_KEYPAIR="${SOLVER_KEYPAIR}"
OP2_KEYPAIR="${CREATOR_KEYPAIR}"
if [[ -n "${CRP_OPERATOR1_KEYPAIR}" ]]; then OP1_KEYPAIR="${CRP_OPERATOR1_KEYPAIR}"; fi
if [[ -n "${CRP_OPERATOR2_KEYPAIR}" ]]; then OP2_KEYPAIR="${CRP_OPERATOR2_KEYPAIR}"; fi

set_stage "fund_keypairs"
if [[ -z "${SOLVER_KEYPAIR_OVERRIDE}" || -z "${SOLVER2_KEYPAIR_OVERRIDE}" || -z "${CREATOR_KEYPAIR_OVERRIDE}" ]]; then
  echo "funding Solana keypairs via devnet airdrop..." >&2
fi
if [[ -z "${SOLVER_KEYPAIR_OVERRIDE}" ]]; then
  airdrop "${SOLVER_PUBKEY}" 2 "${SOLVER_KEYPAIR}"
fi
if [[ -z "${CREATOR_KEYPAIR_OVERRIDE}" ]]; then
  airdrop "${CREATOR_PUBKEY}" 2 "${CREATOR_KEYPAIR}"
fi

min_solver_lamports="${JUNO_E2E_MIN_SOLVER_LAMPORTS:-1500000000}"
min_solver2_lamports="${JUNO_E2E_MIN_SOLVER2_LAMPORTS:-500000000}"
min_creator_lamports="${JUNO_E2E_MIN_CREATOR_LAMPORTS:-500000000}"
solver_balance_now="$(solana_balance_lamports "${SOLVER_PUBKEY}")"
solver2_balance_now="$(solana_balance_lamports "${SOLVER2_PUBKEY}")"
creator_balance_now="$(solana_balance_lamports "${CREATOR_PUBKEY}")"
if [[ "${solver_balance_now}" =~ ^[0-9]+$ && "${solver_balance_now}" -lt "${min_solver_lamports}" ]]; then
  echo "solver balance low (${solver_balance_now} lamports); airdropping 2 SOL..." >&2
  airdrop "${SOLVER_PUBKEY}" 2 "${SOLVER_KEYPAIR}"
fi
if [[ ! "${solver2_balance_now}" =~ ^[0-9]+$ ]]; then solver2_balance_now="0"; fi
if [[ "${solver2_balance_now}" -lt "${min_solver2_lamports}" ]]; then
  if [[ -z "${SOLVER2_KEYPAIR_OVERRIDE}" ]]; then
    echo "solver2 balance low (${solver2_balance_now} lamports); funding from solver..." >&2
    tx_out="$(solana -u "${SOLANA_RPC_URL}" transfer --allow-unfunded-recipient "${SOLVER2_PUBKEY}" 0.5 --keypair "${SOLVER_KEYPAIR}" 2>&1)" || {
      printf '%s\n' "${tx_out}" >&2
      exit 1
    }
    sig="$(printf '%s\n' "${tx_out}" | python3 -c 'import re,sys
raw=sys.stdin.read()
m=re.search(r"[1-9A-HJ-NP-Za-km-z]{80,100}", raw)
print(m.group(0) if m else "")
')"
    if [[ -n "${sig}" ]]; then
      confirm_sig "${sig}" 60
    fi
  else
    echo "solver2 balance low (${solver2_balance_now} lamports); provide JUNO_E2E_SOLVER2_KEYPAIR with funds" >&2
    exit 1
  fi
fi
if [[ "${creator_balance_now}" =~ ^[0-9]+$ && "${creator_balance_now}" -lt "${min_creator_lamports}" ]]; then
  echo "creator balance low (${creator_balance_now} lamports); airdropping 2 SOL..." >&2
  airdrop "${CREATOR_PUBKEY}" 2 "${CREATOR_KEYPAIR}"
fi

set_stage "create_mint"
echo "creating SPL mint + token accounts..." >&2
if ! MINT_OUT="$(spl-token -u "${SOLANA_RPC_URL}" create-token --decimals 0 --owner "${SOLVER_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact 2>&1)"; then
  printf '%s\n' "${MINT_OUT}" >&2
  exit 1
fi
if ! MINT="$(parse_spl_address <<<"${MINT_OUT}")"; then
  echo "failed to parse mint from spl-token output" >&2
  printf '%s\n' "${MINT_OUT}" >&2 || true
  exit 1
fi
MINT_SIG="$(parse_spl_signature <<<"${MINT_OUT}" || true)"
if [[ -n "${MINT_SIG}" ]]; then
  confirm_sig "${MINT_SIG}" 60
fi

SOLVER_TA="$(ata_for "${SOLVER_PUBKEY}" "${MINT}")"
SOLVER2_TA="$(ata_for "${SOLVER2_PUBKEY}" "${MINT}")"
CREATOR_TA="$(ata_for "${CREATOR_PUBKEY}" "${MINT}")"
FEE_TA="$(ata_for "${FEE_COLLECTOR_PUBKEY}" "${MINT}")"

if ! SOLVER_TA_OUT="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${SOLVER_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact 2>&1)"; then
  printf '%s\n' "${SOLVER_TA_OUT}" >&2
  exit 1
fi
SOLVER_TA_SIG="$(parse_spl_signature <<<"${SOLVER_TA_OUT}" || true)"
if [[ -n "${SOLVER_TA_SIG}" ]]; then
  confirm_sig "${SOLVER_TA_SIG}" 60
fi
if ! SOLVER2_TA_OUT="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${SOLVER2_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact 2>&1)"; then
  printf '%s\n' "${SOLVER2_TA_OUT}" >&2
  exit 1
fi
SOLVER2_TA_SIG="$(parse_spl_signature <<<"${SOLVER2_TA_OUT}" || true)"
if [[ -n "${SOLVER2_TA_SIG}" ]]; then
  confirm_sig "${SOLVER2_TA_SIG}" 60
fi
if ! CREATOR_TA_OUT="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${CREATOR_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact 2>&1)"; then
  printf '%s\n' "${CREATOR_TA_OUT}" >&2
  exit 1
fi
CREATOR_TA_SIG="$(parse_spl_signature <<<"${CREATOR_TA_OUT}" || true)"
if [[ -n "${CREATOR_TA_SIG}" ]]; then
  confirm_sig "${CREATOR_TA_SIG}" 60
fi
if ! FEE_TA_OUT="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${FEE_COLLECTOR_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact 2>&1)"; then
  printf '%s\n' "${FEE_TA_OUT}" >&2
  exit 1
fi
FEE_TA_SIG="$(parse_spl_signature <<<"${FEE_TA_OUT}" || true)"
if [[ -n "${FEE_TA_SIG}" ]]; then
  confirm_sig "${FEE_TA_SIG}" 60
fi

echo "mint=${MINT}" >&2
echo "solver_ta=${SOLVER_TA}" >&2
echo "solver2_ta=${SOLVER2_TA}" >&2
echo "creator_ta=${CREATOR_TA}" >&2
echo "fee_ta=${FEE_TA}" >&2

echo "minting tokens..." >&2
for target in "${SOLVER_TA}" "${SOLVER2_TA}" "${CREATOR_TA}"; do
  ok=0
  last_err=""
  for _ in $(seq 1 120); do
    if out="$(spl-token -u "${SOLANA_RPC_URL}" mint "${MINT}" 1000000 "${target}" --mint-authority "${SOLVER_KEYPAIR}" --fee-payer "${SOLVER_KEYPAIR}" 2>&1)"; then
      ok=1
      break
    fi
    last_err="${out}"
    sleep 2
  done
  if [[ "${ok}" != "1" ]]; then
    echo "spl-token mint failed for ${target}" >&2
    printf '%s\n' "${last_err}" >&2
    exit 1
  fi
done

slot="$(curl -fsS -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash"}' \
  "${SOLANA_RPC_URL}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["context"]["slot"])' | tr -d '\r\n ' )"
if [[ -z "${slot}" ]]; then
  echo "failed to fetch current slot" >&2
  exit 1
fi
EXPIRY_SLOT="$((slot + 5000))"
echo "expiry_slot=${EXPIRY_SLOT}" >&2

set_stage "start_solvernet"
echo "starting solvernet quote servers..." >&2
SOLVERNET1_LISTEN="${JUNO_E2E_SOLVERNET1_LISTEN:-127.0.0.1:8081}"
SOLVERNET2_LISTEN="${JUNO_E2E_SOLVERNET2_LISTEN:-127.0.0.1:8082}"
SOLVERNET1_QUOTE_URL="http://${SOLVERNET1_LISTEN}/v1/quote"
SOLVERNET2_QUOTE_URL="http://${SOLVERNET2_LISTEN}/v1/quote"
SOLVERNET1_ANN_URL="http://${SOLVERNET1_LISTEN}/v1/announcement"
SOLVERNET2_ANN_URL="http://${SOLVERNET2_LISTEN}/v1/announcement"

SOLVERNET1_PRICE="${JUNO_E2E_SOLVERNET1_PRICE_ZAT_PER_UNIT:-100000}"
SOLVERNET1_SPREAD="${JUNO_E2E_SOLVERNET1_SPREAD_BPS:-0}"
SOLVERNET2_PRICE="${JUNO_E2E_SOLVERNET2_PRICE_ZAT_PER_UNIT:-110000}"
SOLVERNET2_SPREAD="${JUNO_E2E_SOLVERNET2_SPREAD_BPS:-500}"

"${GO_SOLVERNET}" serve \
  --listen "${SOLVERNET1_LISTEN}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --quote-url "${SOLVERNET1_QUOTE_URL}" \
  --price-zat-per-token-unit "${SOLVERNET1_PRICE}" \
  --spread-bps "${SOLVERNET1_SPREAD}" \
  --keypair "${SOLVER_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" \
  >"${WORKDIR}/solvernet1.log" 2>&1 &
SOLVERNET1_PID="$!"

"${GO_SOLVERNET}" serve \
  --listen "${SOLVERNET2_LISTEN}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --quote-url "${SOLVERNET2_QUOTE_URL}" \
  --price-zat-per-token-unit "${SOLVERNET2_PRICE}" \
  --spread-bps "${SOLVERNET2_SPREAD}" \
  --keypair "${SOLVER2_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" \
  >"${WORKDIR}/solvernet2.log" 2>&1 &
SOLVERNET2_PID="$!"

for _ in $(seq 1 60); do
  if curl -fsS "${SOLVERNET1_ANN_URL}" >/dev/null 2>&1 && curl -fsS "${SOLVERNET2_ANN_URL}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! curl -fsS "${SOLVERNET1_ANN_URL}" >/dev/null 2>&1; then
  echo "solvernet1 announcement not reachable: ${SOLVERNET1_ANN_URL}" >&2
  exit 1
fi
if ! curl -fsS "${SOLVERNET2_ANN_URL}" >/dev/null 2>&1; then
  echo "solvernet2 announcement not reachable: ${SOLVERNET2_ANN_URL}" >&2
  exit 1
fi

set_stage "junocash_setup"
echo "preparing JunoCash accounts, mining, shielding..." >&2

jcli() { "${JUNOCASH_CLI}" "$@"; }

zat_to_junocash_amount() {
  local zat="$1"
  python3 - "$zat" <<'PY'
import sys
zat=int(sys.argv[1])
coin=100000000
whole=zat//coin
frac=zat%coin
print(f"{whole}.{frac:08d}")
PY
}

rfq_best() {
  # Prints: solver_pubkey_base58 <space> amount_zat_u64
  python3 -c 'import json,sys
items=json.load(sys.stdin)
if not isinstance(items, list) or not items:
  raise SystemExit("no quotes")
q=((items[0] or {}).get("signed") or {}).get("quote") or {}
solver=(q.get("solver_pubkey") or "").strip()
amt=q.get("junocash_amount_required")
if not solver or amt is None:
  raise SystemExit("invalid quote")
print(solver, amt)
'
}

select_solver_by_pubkey() {
  local solver_pubkey="$1"
  case "${solver_pubkey}" in
    "${SOLVER_PUBKEY}")
      echo "${SOLVER_KEYPAIR} ${SOLVER_TA} ${SOLVER1_ACCOUNT} ${SOLVER1_UA}"
      ;;
    "${SOLVER2_PUBKEY}")
      echo "${SOLVER2_KEYPAIR} ${SOLVER2_TA} ${SOLVER2_ACCOUNT} ${SOLVER2_UA}"
      ;;
    *)
      echo "unknown solver pubkey: ${solver_pubkey}" >&2
      return 1
      ;;
  esac
}

junocash_dump_docker_logs() {
  if ! command -v docker >/dev/null; then
    return 0
  fi

  local out_dir="${E2E_ARTIFACT_DIR:-${WORKDIR}}"
  if [[ -z "${out_dir}" ]]; then
    return 0
  fi
  mkdir -p "${out_dir}" >/dev/null 2>&1 || true

  local names=()
  local inspect_path log_base log_path
  if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
    names+=("${JUNO_REGTEST_CONTAINER_NAME:-juno-regtest}")
  else
    names+=("${JUNO_TESTNET_CONTAINER_NAME_A:-juno-testnet-a}")
    names+=("${JUNO_TESTNET_CONTAINER_NAME_B:-juno-testnet-b}")
  fi

  for name in "${names[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -qx "${name}"; then
      if ! docker ps --format '{{.Names}}' | grep -qx "${name}"; then
        echo "junocash container exited: ${name}" >&2
      fi
      inspect_path="${out_dir}/junocash-${name}.docker.inspect.json"
      docker inspect "${name}" >"${inspect_path}" 2>/dev/null || true

      log_base="${out_dir}/junocash-${name}.docker.log"
      if command -v gzip >/dev/null; then
        log_path="${log_base}.gz"
        docker logs --tail 200 "${name}" 2>&1 | gzip -c >"${log_path}" || true
      else
        log_path="${log_base}"
        docker logs --tail 200 "${name}" >"${log_path}" 2>&1 || true
      fi

      echo "junocash docker logs saved: ${log_path}" >&2
      echo "junocash docker inspect saved: ${inspect_path}" >&2
    fi
  done
}

junocash_op_status_summary() {
  local opid="$1"
  local st
  st="$(jcli z_getoperationstatus "[\"${opid}\"]" 2>/dev/null || true)"
  if [[ -z "${st}" ]]; then
    return 0
  fi
  python3 - "${opid}" <<'PY' <<<"${st}"
import json,sys
opid=sys.argv[1]
raw=sys.stdin.read()
try:
  items=json.loads(raw)
except Exception:
  print(f"op_status=unparseable opid={opid}")
  raise SystemExit(0)
it=(items[0] if isinstance(items, list) and items else {}) or {}
status=str(it.get("status") or "").strip()
method=str(it.get("method") or "").strip()
msg=""
err=it.get("error")
if isinstance(err, dict):
  msg=str(err.get("message") or err.get("code") or "").strip()
elif err is not None:
  msg=str(err).strip()
extra=""
if msg:
  extra=" message="+msg.replace("\\n"," ")[:200]
print(f"op_status={status or 'unknown'} method={method or 'unknown'} opid={opid}{extra}")
PY
}

junocash_save_op_debug() {
  local opid="$1"
  local out_dir="${E2E_ARTIFACT_DIR:-${WORKDIR}}"
  if [[ -z "${out_dir}" ]]; then
    return 0
  fi
  mkdir -p "${out_dir}" >/dev/null 2>&1 || true

  local safe
  safe="$(printf '%s' "${opid}" | tr -cs 'a-zA-Z0-9._-' '_' )"
  jcli z_getoperationstatus "[\"${opid}\"]" >"${out_dir}/junocash-opstatus-${safe}.json" 2>/dev/null || true
  jcli z_getoperationresult "[\"${opid}\"]" >"${out_dir}/junocash-opresult-${safe}.json" 2>/dev/null || true
}

wait_for_wallet_scan_complete() {
  local wait_secs="${1:-3600}"
  local progress_secs="${2:-30}"
  local elapsed=0
  local info summary done
  local err_short

  if ! [[ "${wait_secs}" =~ ^[0-9]+$ ]] || [[ "${wait_secs}" -le 0 ]]; then
    wait_secs="3600"
  fi
  if ! [[ "${progress_secs}" =~ ^[0-9]+$ ]] || [[ "${progress_secs}" -le 0 ]]; then
    progress_secs="30"
  fi

  echo "waiting for wallet scan to complete..." >&2
  while [[ "${elapsed}" -lt "${wait_secs}" ]]; do
    info="$(jcli getwalletinfo 2>&1 || true)"
    if [[ -n "${info}" ]]; then
      if [[ "${info}" == error\ code:* ]]; then
        if (( elapsed % progress_secs == 0 )); then
          err_short="$(printf '%s\n' "${info}" | head -n 3 | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/ $//')"
          if [[ -n "${err_short}" ]]; then
            echo "wallet_scan rpc_error=$(printf '%s' "${err_short}" | tr ' ' '_') elapsed=${elapsed}s" >&2
          fi
        fi
        sleep 1
        elapsed="$((elapsed + 1))"
        continue
      fi
      read -r done summary <<<"$(
        python3 -c 'import json,sys
try:
  j=json.load(sys.stdin)
except Exception:
  print("0", "unparseable")
  raise SystemExit(0)
sc=j.get("scanning", None)
if sc is False or sc is None:
  print("1", "done")
  raise SystemExit(0)
if isinstance(sc, dict):
  prog=sc.get("progress")
  dur=sc.get("duration")
  parts=[]
  if prog is not None:
    try:
      parts.append(f"progress={float(prog):.4f}")
    except Exception:
      parts.append(f"progress={prog}")
  if dur is not None:
    parts.append(f"duration={dur}")
  msg="scanning " + (" ".join(parts) if parts else "active")
  print("0", msg.replace(" ", "_"))
  raise SystemExit(0)
print("0", "scanning")
' <<<"${info}"
      )"
      if [[ "${done}" == "1" ]]; then
        return 0
      fi
      if (( elapsed % progress_secs == 0 )); then
        echo "wallet_scan ${summary} elapsed=${elapsed}s" >&2
      fi
    fi
    sleep 1
    elapsed="$((elapsed + 1))"
  done

  echo "wallet scan did not complete (elapsed=${elapsed}s timeout=${wait_secs}s)" >&2
  printf '%s\n' "${info}" >&2
  return 1
}

wait_for_op_txid() {
  local opid="$1"
  local wait_secs="${2:-1800}"

  local last_nonjson=""
  local nonjson_count=0
  local empty_count=0
  local i=0
  for i in $(seq 1 "${wait_secs}"); do
    res="$(jcli z_getoperationresult "[\"${opid}\"]" 2>/dev/null || true)"
    compact="$(printf '%s' "${res}" | tr -d ' \n\r\t')"
    if [[ -z "${compact}" ]]; then
      # Treat empty output as transient RPC failure.
      empty_count="$((empty_count + 1))"
      if (( empty_count == 30 || empty_count % 120 == 0 )); then
        echo "z_getoperationresult returned empty output (opid=${opid} count=${empty_count})" >&2
        junocash_op_status_summary "${opid}" >&2 || true
        if command -v docker >/dev/null; then
          if [[ "${JUNOCASH_CHAIN}" == "testnet" ]]; then
            name_a="${JUNO_TESTNET_CONTAINER_NAME_A:-juno-testnet-a}"
            if docker ps -a --format '{{.Names}}' | grep -qx "${name_a}" && ! docker ps --format '{{.Names}}' | grep -qx "${name_a}"; then
              junocash_save_op_debug "${opid}" || true
              junocash_dump_docker_logs
              return 1
            fi
          else
            name="${JUNO_REGTEST_CONTAINER_NAME:-juno-regtest}"
            if docker ps -a --format '{{.Names}}' | grep -qx "${name}" && ! docker ps --format '{{.Names}}' | grep -qx "${name}"; then
              junocash_save_op_debug "${opid}" || true
              junocash_dump_docker_logs
              return 1
            fi
          fi
        fi
      fi
      sleep 1
      continue
    fi
    empty_count=0
    if [[ "${compact}" == "[]" ]]; then
      if (( i == 1 || i % 120 == 0 )); then
        junocash_op_status_summary "${opid}" >&2 || true
      fi
      sleep 1
      continue
    fi

    # Some CLI/RPC failures print non-JSON output to stdout/stderr; keep waiting.
    if [[ "${compact}" != \[* ]]; then
      last_nonjson="${res}"
      nonjson_count="$((nonjson_count + 1))"
      if (( nonjson_count == 1 || nonjson_count % 30 == 0 )); then
        echo "z_getoperationresult returned non-JSON (opid=${opid} count=${nonjson_count})" >&2
        printf '%s\n' "${res}" | head -n 5 >&2 || true
      fi
      sleep 1
      continue
    fi

    parsed=""
    if parsed="$(python3 -c 'import json,sys
items=json.load(sys.stdin)
it=items[0] if items else {}
status=it.get("status")
if status=="success":
  txid=(it.get("result") or {}).get("txid") or ""
  print(txid)
  sys.exit(0 if txid else 3)
err=it.get("error")
msg=err.get("message") if isinstance(err, dict) else err
print(f"status={status} message={msg}")
sys.exit(2)
' <<<"${res}")"; then
      printf '%s\n' "${parsed}"
      return 0
    else
      ec=$?
      if [[ "${ec}" == "2" ]]; then
        echo "operation failed: ${parsed} (opid=${opid})" >&2
        printf '%s\n' "${res}" >&2
        junocash_save_op_debug "${opid}" || true
        return 1
      fi
      if [[ "${ec}" == "3" ]]; then
        echo "operation completed without txid (opid=${opid})" >&2
        printf '%s\n' "${res}" >&2
        junocash_save_op_debug "${opid}" || true
        return 1
      fi
      echo "unexpected z_getoperationresult parser exit code: ${ec} (opid=${opid})" >&2
      printf '%s\n' "${res}" >&2
      junocash_save_op_debug "${opid}" || true
      return 1
    fi
  done

  echo "operation did not complete (opid=${opid})" >&2
  junocash_op_status_summary "${opid}" >&2 || true
  junocash_save_op_debug "${opid}" || true
  junocash_dump_docker_logs || true
  if [[ -n "${last_nonjson}" ]]; then
    echo "last non-JSON z_getoperationresult output (opid=${opid}):" >&2
    printf '%s\n' "${last_nonjson}" >&2
  fi
  return 1
}

wait_for_testnet_sync() {
  local timeout_secs="${1:-7200}"
  local poll_secs="${2:-5}"
  local progress_secs="${3:-30}"
  local elapsed=0
  local info complete summary

  if ! [[ "${timeout_secs}" =~ ^[0-9]+$ ]] || [[ "${timeout_secs}" -le 0 ]]; then
    timeout_secs="7200"
  fi
  if ! [[ "${poll_secs}" =~ ^[0-9]+$ ]] || [[ "${poll_secs}" -le 0 ]]; then
    poll_secs="5"
  fi
  if ! [[ "${progress_secs}" =~ ^[0-9]+$ ]] || [[ "${progress_secs}" -le 0 ]]; then
    progress_secs="30"
  fi

  echo "waiting for testnet sync (initial_block_download_complete=true)..." >&2
  while [[ "${elapsed}" -lt "${timeout_secs}" ]]; do
    info="$(jcli getblockchaininfo 2>/dev/null || true)"
    if [[ -n "${info}" ]]; then
      complete="$(
        python3 -c 'import json,sys
try:
  j=json.load(sys.stdin)
except Exception:
  print("0"); raise SystemExit(0)
print("1" if j.get("initial_block_download_complete") else "0")
' <<<"${info}"
      )"
      if [[ "${complete}" == "1" ]]; then
        return 0
      fi
      if (( elapsed % progress_secs == 0 )); then
        summary="$(
          python3 -c 'import json,sys
try: j=json.load(sys.stdin)
except Exception: print(""); raise SystemExit(0)
blocks=j.get("blocks"); headers=j.get("headers"); est=j.get("estimatedheight")
print(f"blocks={blocks} headers={headers} estimatedheight={est}")
' <<<"${info}"
        )"
        if [[ -n "${summary}" ]]; then
          echo "sync_status ${summary} elapsed=${elapsed}s" >&2
        fi
      fi
    fi
    sleep "${poll_secs}"
    elapsed="$((elapsed + poll_secs))"
  done

  echo "timed out waiting for testnet sync (elapsed=${elapsed}s timeout=${timeout_secs}s)" >&2
  return 1
}

wait_for_tx_confirmations() {
  local txid="$1"
  local minconf="${2:-1}"
  local wait_secs="${3:-1800}"
  local raw conf blockhash header height

  if [[ -z "${txid}" ]]; then
    echo "wait_for_tx_confirmations: txid required" >&2
    return 2
  fi
  if ! [[ "${minconf}" =~ ^[0-9]+$ ]] || [[ "${minconf}" -le 0 ]]; then
    minconf="1"
  fi
  if ! [[ "${wait_secs}" =~ ^[0-9]+$ ]] || [[ "${wait_secs}" -le 0 ]]; then
    wait_secs="1800"
  fi

  for _ in $(seq 1 "${wait_secs}"); do
    raw="$(jcli gettransaction "${txid}" 2>/dev/null || true)"
    if [[ -z "${raw}" ]]; then
      # Fallback for non-wallet transactions when txindex is enabled.
      raw="$(jcli getrawtransaction "${txid}" 1 2>/dev/null || true)"
    fi
    if [[ -z "${raw}" ]]; then
      sleep 1
      continue
    fi
    read -r conf blockhash <<<"$(
      python3 -c 'import json,sys
j=json.load(sys.stdin)
conf=int(j.get("confirmations") or 0)
bh=(j.get("blockhash") or "").strip()
print(conf, bh)
' <<<"${raw}"
    )"
    if [[ -z "${conf}" || ! "${conf}" =~ ^[0-9]+$ ]]; then
      sleep 1
      continue
    fi
    if [[ "${conf}" -ge "${minconf}" ]]; then
      if [[ -z "${blockhash}" ]]; then
        echo "tx confirmed but missing blockhash: ${txid} (conf=${conf})" >&2
        return 1
      fi
      header="$(jcli getblockheader "${blockhash}" 1 2>/dev/null || true)"
      height="$(
        python3 -c 'import json,sys
j=json.load(sys.stdin)
print(int(j.get("height") or 0))
' <<<"${header}"
      )"
      if [[ -z "${height}" || ! "${height}" =~ ^[0-9]+$ || "${height}" -le 0 ]]; then
        echo "failed to parse confirmed tx height: ${txid} (blockhash=${blockhash})" >&2
        printf '%s\n' "${header}" >&2
        return 1
      fi
      printf '%s\n' "${height}"
      return 0
    fi
    sleep 1
  done

  echo "timeout waiting for confirmations (txid=${txid} minconf=${minconf} wait_secs=${wait_secs})" >&2
  return 1
}

use_wallet_prefund="false"
use_taddr_prefund="false"
if [[ "${JUNOCASH_CHAIN}" == "testnet" ]]; then
  if [[ -n "${JUNOCASH_TESTNET_WALLET_DAT_GZ_B64}" ]]; then
    use_wallet_prefund="true"
  elif [[ -n "${JUNOCASH_TESTNET_PREFUND_WIF}" ]]; then
    use_taddr_prefund="true"
  fi
fi

if [[ "${use_wallet_prefund}" == "true" ]]; then
  echo "using prefunded testnet wallet.dat (shielded)..." >&2
  sync_timeout="${JUNO_TESTNET_SYNC_TIMEOUT_SECS:-7200}"
  sync_poll_secs="${JUNO_TESTNET_SYNC_POLL_SECS:-5}"
  sync_progress_secs="${JUNO_TESTNET_SYNC_PROGRESS_SECS:-30}"
  wait_for_testnet_sync "${sync_timeout}" "${sync_poll_secs}" "${sync_progress_secs}"
  wallet_scan_timeout="${JUNO_E2E_WALLET_SCAN_TIMEOUT_SECS:-3600}"
  wait_for_wallet_scan_complete "${wallet_scan_timeout}" 30
elif [[ "${use_taddr_prefund}" == "true" ]]; then
  echo "using prefunded testnet transparent key (skipping coinbase mining)..." >&2
  sync_timeout="${JUNO_TESTNET_SYNC_TIMEOUT_SECS:-7200}"
  sync_poll_secs="${JUNO_TESTNET_SYNC_POLL_SECS:-5}"
  sync_progress_secs="${JUNO_TESTNET_SYNC_PROGRESS_SECS:-30}"
  wait_for_testnet_sync "${sync_timeout}" "${sync_poll_secs}" "${sync_progress_secs}"

  echo "importing prefunded testnet key (importprivkey + rescan)..." >&2
  jcli importprivkey "${JUNOCASH_TESTNET_PREFUND_WIF}" "e2e-testnet-prefund" true >/dev/null
  wallet_scan_timeout="${JUNO_E2E_WALLET_SCAN_TIMEOUT_SECS:-3600}"
  wait_for_wallet_scan_complete "${wallet_scan_timeout}" 30
else
  echo "mining initial blocks for coinbase maturity..." >&2
  if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
    jcli generate 110 >/dev/null
  else
    mine_timeout="${JUNO_E2E_COINBASE_MINE_TIMEOUT_SECS:-3600}"
    echo "coinbase_mine_timeout_secs=${mine_timeout}" >&2
    JUNO_TESTNET_MINE_TIMEOUT_SECS="${mine_timeout}" scripts/junocash/testnet/mine.sh 110 >/dev/null
  fi
fi

echo "creating JunoCash accounts + orchard UAs..." >&2
if [[ "${use_wallet_prefund}" == "true" ]]; then
  read -r USER_ACCOUNT USER_UA <<<"$(
    jcli z_listaccounts | python3 -c 'import json,sys
items=json.load(sys.stdin)
if not isinstance(items, list) or not items:
  raise SystemExit("no accounts in wallet")
it=items[0] or {}
acct=it.get("account")
addrs=it.get("addresses") or []
ua=((addrs[0] or {}).get("ua") or "").strip() if addrs else ""
if acct is None or ua == "":
  raise SystemExit("failed to parse z_listaccounts")
print(int(acct), ua)
'
  )"
else
  USER_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
  USER_UA="$(jcli z_getaddressforaccount "${USER_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
fi
SOLVER1_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
SOLVER2_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
SOLVER1_UA="$(jcli z_getaddressforaccount "${SOLVER1_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
SOLVER2_UA="$(jcli z_getaddressforaccount "${SOLVER2_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
echo "user_account=${USER_ACCOUNT}" >&2
echo "solver1_account=${SOLVER1_ACCOUNT}" >&2
echo "solver2_account=${SOLVER2_ACCOUNT}" >&2
echo "user_ua=${USER_UA}" >&2
echo "solver1_ua=${SOLVER1_UA}" >&2
echo "solver2_ua=${SOLVER2_UA}" >&2

if [[ "${use_taddr_prefund}" == "true" ]]; then
  echo "funding user orchard UA from ANY_TADDR (amount=${JUNOCASH_TESTNET_PREFUND_AMOUNT})..." >&2
  _prefund_amount_ok="$(
    python3 -c 'from decimal import Decimal; import sys
s=sys.argv[1]
try:
  d=Decimal(s)
except Exception:
  raise SystemExit(1)
if d<=0:
  raise SystemExit(1)
print(str(d))
' "${JUNOCASH_TESTNET_PREFUND_AMOUNT}" 2>/dev/null || true
  )"
  if [[ -z "${_prefund_amount_ok}" ]]; then
    echo "invalid JUNO_E2E_JUNOCASH_TESTNET_PREFUND_AMOUNT: ${JUNOCASH_TESTNET_PREFUND_AMOUNT}" >&2
    exit 2
  fi
  recipients_prefund="$(python3 -c 'import json,sys
addr=sys.argv[1]; amt=sys.argv[2]
print(json.dumps([{"address":addr,"amount":float(amt)}]))
' "${USER_UA}" "${_prefund_amount_ok}")"
  prefund_out=""
  if ! prefund_out="$(jcli z_sendmany "ANY_TADDR" "${recipients_prefund}" "${JUNOCASH_SEND_MINCONF}" 2>&1)"; then
    echo "prefund via ANY_TADDR failed; falling back to z_shieldcoinbase..." >&2
    printf '%s\n' "${prefund_out}" >&2
    opid_prefund="$(jcli z_shieldcoinbase "*" "${USER_UA}" null "${JUNOCASH_SHIELD_LIMIT}" | parse_junocash_opid)"
  else
    opid_prefund="$(printf '%s' "${prefund_out}" | parse_junocash_opid)"
  fi
  txid_prefund="$(wait_for_op_txid "${opid_prefund}" 1800)"
  echo "txid_prefund=${txid_prefund}" >&2

  echo "waiting for prefund tx confirmation..." >&2
  scripts/junocash/testnet/mine.sh 1 >/dev/null
  prefund_height="$(wait_for_tx_confirmations "${txid_prefund}" 1 600)"
  echo "prefund_height=${prefund_height}" >&2
elif [[ "${use_wallet_prefund}" == "true" ]]; then
  echo "prefunded wallet selected; skipping coinbase shielding" >&2
else
  echo "checking coinbase maturity (wallet balance)..." >&2
  min_mature_zat="${JUNO_E2E_MIN_MATURE_COINBASE_ZAT:-10000}" # 0.0001 JunoCash
  max_extra_blocks="${JUNO_E2E_MAX_COINBASE_MATURITY_BLOCKS:-2000}"
  step_blocks="${JUNO_E2E_COINBASE_MATURITY_STEP_BLOCKS:-50}"
  extra_mined=0
  no_funds_wait_secs="${JUNO_E2E_COINBASE_WALLET_WAIT_SECS:-180}"
  no_funds_waited=0
  while true; do
    wallet_info="$(jcli getwalletinfo 2>&1)" || {
      printf '%s\n' "${wallet_info}" >&2
      exit 1
    }
    read -r mature_zat immature_zat <<<"$(
      python3 -c 'import json,sys
from decimal import Decimal
j=json.load(sys.stdin)
def to_zat(v):
  if v is None:
    return 0
  d=Decimal(str(v))
  return int(d * Decimal(100000000))
print(to_zat(j.get("balance")), to_zat(j.get("immature_balance")))
' <<<"${wallet_info}"
    )"
    if [[ -z "${mature_zat}" || -z "${immature_zat}" || ! "${mature_zat}" =~ ^[0-9]+$ || ! "${immature_zat}" =~ ^[0-9]+$ ]]; then
      echo "failed to parse getwalletinfo balance fields" >&2
      printf '%s\n' "${wallet_info}" >&2
      exit 1
    fi
    echo "wallet_balance_zat=${mature_zat} wallet_immature_zat=${immature_zat}" >&2
    if [[ "${mature_zat}" -ge "${min_mature_zat}" ]]; then
      break
    fi
    if [[ "${mature_zat}" -eq 0 && "${immature_zat}" -eq 0 ]]; then
      if [[ "${no_funds_waited}" -lt "${no_funds_wait_secs}" ]]; then
        echo "wallet has no coinbase yet; waiting 5s for wallet to catch up..." >&2
        sleep 5
        no_funds_waited="$((no_funds_waited + 5))"
        continue
      fi
      echo "wallet still has no coinbase after waiting ${no_funds_waited}s" >&2
      exit 1
    fi
    if [[ "${extra_mined}" -ge "${max_extra_blocks}" ]]; then
      echo "coinbase did not mature after mining extra blocks (extra_mined=${extra_mined} max=${max_extra_blocks})" >&2
      exit 1
    fi
    echo "coinbase still immature; mining ${step_blocks} more blocks..." >&2
    if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
      jcli generate "${step_blocks}" >/dev/null
    else
      scripts/junocash/testnet/mine.sh "${step_blocks}" >/dev/null
    fi
    extra_mined="$((extra_mined + step_blocks))"
    no_funds_waited=0
  done

  echo "shielding coinbase to user orchard UA..." >&2
  opid="$(jcli z_shieldcoinbase "*" "${USER_UA}" null "${JUNOCASH_SHIELD_LIMIT}" | parse_junocash_opid)"

  echo "waiting for shield operation..." >&2
  txid_shield="$(wait_for_op_txid "${opid}" 1800)"
  echo "txid_shield=${txid_shield}" >&2

  echo "waiting for shield tx confirmation..." >&2
  if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
    jcli generate 1 >/dev/null
  else
    scripts/junocash/testnet/mine.sh 1 >/dev/null
    shield_height="$(wait_for_tx_confirmations "${txid_shield}" 1 600)"
    echo "shield_height=${shield_height}" >&2
  fi
fi

echo "waiting for user orchard note to be spendable..." >&2
user_note_ok="false"
note_wait_secs="${JUNO_E2E_USER_NOTE_WAIT_SECS:-1800}"
note_progress_secs="${JUNO_E2E_USER_NOTE_PROGRESS_SECS:-30}"
if ! [[ "${note_wait_secs}" =~ ^[0-9]+$ ]] || [[ "${note_wait_secs}" -le 0 ]]; then
  note_wait_secs="1800"
fi
if ! [[ "${note_progress_secs}" =~ ^[0-9]+$ ]] || [[ "${note_progress_secs}" -le 0 ]]; then
  note_progress_secs="30"
fi
user_note_elapsed=0
last_unspent=""
while [[ "${user_note_elapsed}" -lt "${note_wait_secs}" ]]; do
  unspent="$(jcli z_listunspent 1 9999999 false 2>&1 || true)"
  last_unspent="${unspent}"
  if python3 -c "import json,sys
try:
  notes=json.load(sys.stdin)
except Exception:
  raise SystemExit(1)
acct=int(\"${USER_ACCOUNT}\")
ok=any(n.get('pool')=='orchard' and n.get('spendable') and n.get('account')==acct for n in notes)
raise SystemExit(0 if ok else 1)
" <<<"${unspent}"; then
    user_note_ok="true"
    break
  fi
  if (( user_note_elapsed % note_progress_secs == 0 )); then
    if [[ "${unspent}" == error\ code:* ]]; then
      err_short="$(printf '%s\n' "${unspent}" | head -n 3 | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/ $//')"
      if [[ -n "${err_short}" ]]; then
        echo "user_note_wait rpc_error=$(printf '%s' "${err_short}" | tr ' ' '_') elapsed=${user_note_elapsed}s" >&2
      fi
    else
      echo "user_note_wait elapsed=${user_note_elapsed}s" >&2
    fi
  fi
  sleep 1
  user_note_elapsed="$((user_note_elapsed + 1))"
done
if [[ "${user_note_ok}" != "true" ]]; then
  echo "user orchard note did not become spendable" >&2
  if [[ -n "${last_unspent}" ]]; then
    printf '%s\n' "${last_unspent}" | head -n 20 >&2 || true
  fi
  junocash_dump_docker_logs || true
  exit 1
fi

DATA_DIR="${JUNOCASH_DATA_DIR}"
if [[ "${DATA_DIR}" != /* ]]; then
  DATA_DIR="${ROOT}/${DATA_DIR}"
fi
wallet_candidates=(
  "${DATA_DIR}/wallet.dat"
  "${DATA_DIR}/testnet3/wallet.dat"
  "${DATA_DIR}/regtest/wallet.dat"
  "${DATA_DIR}/wallets/wallet.dat"
  "${DATA_DIR}/testnet3/wallets/wallet.dat"
  "${DATA_DIR}/regtest/wallets/wallet.dat"
)
WALLET_DAT=""
for p in "${wallet_candidates[@]}"; do
  if [[ -f "${p}" ]]; then
    WALLET_DAT="${p}"
    break
  fi
done
if [[ -z "${WALLET_DAT}" ]]; then
  echo "wallet.dat not found under ${DATA_DIR}" >&2
  exit 1
fi
echo "wallet_dat=${WALLET_DAT}" >&2

set_stage "direction_a"
echo "=== Direction A (JunoCash -> Solana) ===" >&2

create_intent_a_raw=""
if ! create_intent_a_raw="$("${GO_INTENTS}" iep-create-intent \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --mint "${MINT}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --net-amount "${NET_AMOUNT_A}" \
  --expiry-slot "${EXPIRY_SLOT}" \
  --direction A \
  --creator-keypair "${CREATOR_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" \
  2>&1)"; then
  printf '%s\n' "${create_intent_a_raw}" >&2
  exit 1
fi
INTENT_A="$(printf '%s\n' "${create_intent_a_raw}" | sed -nE 's/^intent=([1-9A-HJ-NP-Za-km-z]+)$/\1/p' | head -n 1)"
if [[ -z "${INTENT_A}" ]]; then
  echo "failed to parse intent A" >&2
  printf '%s\n' "${create_intent_a_raw}" >&2
  exit 1
fi
echo "intent_a=${INTENT_A}" >&2

FILL_ID_A="$("${GO_INTENTS}" iep-pdas --deployment "${DEPLOYMENT_NAME}" --deployment-file "${DEPLOYMENT_FILE}" --intent "${INTENT_A}" --print fill-id-hex)"
echo "fill_id_a=${FILL_ID_A}" >&2

echo "requesting solver quotes (A)..." >&2
rfq_a="$("${GO_SOLVERNET}" rfq \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --direction A \
  --mint "${MINT}" \
  --net-amount "${NET_AMOUNT_A}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --intent-expiry-slot "${EXPIRY_SLOT}" \
  --announcement-url "${SOLVERNET1_ANN_URL}" \
  --announcement-url "${SOLVERNET2_ANN_URL}" \
  2>"${WORKDIR}/rfq_a.stderr")" || {
  echo "solvernet rfq (A) failed" >&2
  printf '%s\n' "--- rfq_a.stderr ---" >&2
  cat "${WORKDIR}/rfq_a.stderr" >&2 || true
  printf '%s\n' "--- solvernet1.log ---" >&2
  tail -n 200 "${WORKDIR}/solvernet1.log" >&2 || true
  printf '%s\n' "--- solvernet2.log ---" >&2
  tail -n 200 "${WORKDIR}/solvernet2.log" >&2 || true
  exit 1
}
if [[ -z "${rfq_a}" ]]; then
  echo "solvernet rfq (A) returned empty output" >&2
  cat "${WORKDIR}/rfq_a.stderr" >&2 || true
  exit 1
fi
printf '%s\n' "${rfq_a}" >"${WORKDIR}/rfq_a.json"
best_a="$(rfq_best <<<"${rfq_a}")" || {
  echo "solvernet rfq (A) returned no usable quotes" >&2
  exit 1
}
read -r SOLVER_A_PUBKEY AMOUNT_A_ZAT <<<"${best_a}"
solver_a_info="$(select_solver_by_pubkey "${SOLVER_A_PUBKEY}")" || exit 1
read -r SOLVER_A_KEYPAIR SOLVER_A_TA SOLVER_A_ACCOUNT SOLVER_A_UA <<<"${solver_a_info}"
PAYMENT_AMOUNT_A_STR="$(zat_to_junocash_amount "${AMOUNT_A_ZAT}")"
echo "solver_a_pubkey=${SOLVER_A_PUBKEY}" >&2
echo "solver_a_ua=${SOLVER_A_UA}" >&2
echo "quote_amount_a_zat=${AMOUNT_A_ZAT} (${PAYMENT_AMOUNT_A_STR})" >&2

echo "sending JunoCash payment user->solver (amount=${PAYMENT_AMOUNT_A_STR})..." >&2
recipients_a="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${SOLVER_A_UA}" "${PAYMENT_AMOUNT_A_STR}")"
opid_a="$(jcli z_sendmany "${USER_UA}" "${recipients_a}" "${JUNOCASH_SEND_MINCONF}" | parse_junocash_opid)"

echo "waiting for sendmany operation (A)..." >&2
txid_a="$(wait_for_op_txid "${opid_a}" 1800)"
echo "txid_a=${txid_a}" >&2

height_a_before="$(jcli getblockcount)"
if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
  echo "mining block to include payment tx (A)..." >&2
  jcli generate 1 >/dev/null
  height_a_after="$(jcli getblockcount)"
  PAYMENT_HEIGHT_A="${height_a_after}"
  echo "payment_height_a=${PAYMENT_HEIGHT_A} (before=${height_a_before} after=${height_a_after})" >&2
else
  echo "mining block to include payment tx (A)..." >&2
  scripts/junocash/testnet/mine.sh 1 >/dev/null
  PAYMENT_HEIGHT_A="$(wait_for_tx_confirmations "${txid_a}" 1 600)"
  echo "payment_height_a=${PAYMENT_HEIGHT_A} (before=${height_a_before})" >&2
fi

  echo "waiting for solver orchard note to appear (A)..." >&2
  ACTION_A=""
  for _ in $(seq 1 1800); do
  ACTION_A="$(jcli z_listunspent 1 9999999 false | python3 -c 'import json,sys
txid=sys.argv[1].strip().lower()
acct=int(sys.argv[2])
notes=json.load(sys.stdin)
for n in notes:
  if str(n.get("pool",""))!="orchard":
    continue
  if str(n.get("txid","")).strip().lower()!=txid:
    continue
  if n.get("account")!=acct:
    continue
  if not n.get("spendable"):
    continue
  print(n.get("outindex"))
  sys.exit(0)
sys.exit(1)
' "${txid_a}" "${SOLVER_A_ACCOUNT}")" && break || true
    sleep 1
  done
  if [[ -z "${ACTION_A}" ]]; then
    echo "failed to find solver note outindex for tx A" >&2
  exit 1
fi
echo "action_a=${ACTION_A}" >&2

echo "generating receipt witness (A)..." >&2
WITNESS_A="$(cd "${ROOT}" && cargo run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli "${JUNOCASH_CLI}" \
  --wallet "${WALLET_DAT}" \
  --txid "${txid_a}" \
  --action "${ACTION_A}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_A}")"

INPUTS_A="$("${GO_INTENTS}" receipt-inputs --witness-hex "${WITNESS_A}" --json=false)"
AMOUNT_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^amount=([0-9]+)$/\1/p' | head -n 1)"
RECEIVER_TAG_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^receiver_tag=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
ORCHARD_ROOT_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^orchard_root=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
if [[ -n "${AMOUNT_A_ZAT:-}" && "${AMOUNT_A}" != "${AMOUNT_A_ZAT}" ]]; then
  echo "quote/witness amount mismatch (A): quote=${AMOUNT_A_ZAT} witness=${AMOUNT_A}" >&2
  exit 1
fi
echo "orchard_root_a=${ORCHARD_ROOT_A}" >&2
echo "receiver_tag_a=${RECEIVER_TAG_A}" >&2
echo "junocash_amount_a_zat=${AMOUNT_A}" >&2

echo "waiting for +1 confirmation (reorg safety)..." >&2
if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
  jcli generate 1 >/dev/null
else
  scripts/junocash/testnet/mine.sh 1 >/dev/null
  wait_for_tx_confirmations "${txid_a}" 2 600 >/dev/null
fi

set_stage "direction_b"
echo "=== Direction B (Solana -> JunoCash) ===" >&2

create_intent_b_raw=""
if ! create_intent_b_raw="$("${GO_INTENTS}" iep-create-intent \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --mint "${MINT}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --net-amount "${NET_AMOUNT_B}" \
  --expiry-slot "${EXPIRY_SLOT}" \
  --direction B \
  --creator-keypair "${CREATOR_KEYPAIR}" \
  --creator-source-token-account "${CREATOR_TA}" \
  --priority-level "${PRIORITY_LEVEL}" \
  2>&1)"; then
  printf '%s\n' "${create_intent_b_raw}" >&2
  exit 1
fi
INTENT_B="$(printf '%s\n' "${create_intent_b_raw}" | sed -nE 's/^intent=([1-9A-HJ-NP-Za-km-z]+)$/\1/p' | head -n 1)"
if [[ -z "${INTENT_B}" ]]; then
  echo "failed to parse intent B" >&2
  printf '%s\n' "${create_intent_b_raw}" >&2
  exit 1
fi
echo "intent_b=${INTENT_B}" >&2

FILL_ID_B="$("${GO_INTENTS}" iep-pdas --deployment "${DEPLOYMENT_NAME}" --deployment-file "${DEPLOYMENT_FILE}" --intent "${INTENT_B}" --print fill-id-hex)"
echo "fill_id_b=${FILL_ID_B}" >&2

echo "requesting solver quotes (B)..." >&2
rfq_b="$("${GO_SOLVERNET}" rfq \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --direction B \
  --mint "${MINT}" \
  --net-amount "${NET_AMOUNT_B}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --intent-expiry-slot "${EXPIRY_SLOT}" \
  --announcement-url "${SOLVERNET1_ANN_URL}" \
  --announcement-url "${SOLVERNET2_ANN_URL}" \
  2>"${WORKDIR}/rfq_b.stderr")" || {
  echo "solvernet rfq (B) failed" >&2
  printf '%s\n' "--- rfq_b.stderr ---" >&2
  cat "${WORKDIR}/rfq_b.stderr" >&2 || true
  printf '%s\n' "--- solvernet1.log ---" >&2
  tail -n 200 "${WORKDIR}/solvernet1.log" >&2 || true
  printf '%s\n' "--- solvernet2.log ---" >&2
  tail -n 200 "${WORKDIR}/solvernet2.log" >&2 || true
  exit 1
}
if [[ -z "${rfq_b}" ]]; then
  echo "solvernet rfq (B) returned empty output" >&2
  cat "${WORKDIR}/rfq_b.stderr" >&2 || true
  exit 1
fi
printf '%s\n' "${rfq_b}" >"${WORKDIR}/rfq_b.json"
best_b="$(rfq_best <<<"${rfq_b}")" || {
  echo "solvernet rfq (B) returned no usable quotes" >&2
  exit 1
}
read -r SOLVER_B_PUBKEY AMOUNT_B_ZAT <<<"${best_b}"
solver_b_info="$(select_solver_by_pubkey "${SOLVER_B_PUBKEY}")" || exit 1
read -r SOLVER_B_KEYPAIR SOLVER_B_TA SOLVER_B_ACCOUNT SOLVER_B_UA <<<"${solver_b_info}"
PAYMENT_AMOUNT_B_STR="$(zat_to_junocash_amount "${AMOUNT_B_ZAT}")"
echo "solver_b_pubkey=${SOLVER_B_PUBKEY}" >&2
echo "solver_b_ua=${SOLVER_B_UA}" >&2
echo "quote_amount_b_zat=${AMOUNT_B_ZAT} (${PAYMENT_AMOUNT_B_STR})" >&2

if [[ "${SOLVER_B_UA}" != "${SOLVER_A_UA}" ]]; then
  echo "funding solver B from user (so it can pay on JunoCash)..." >&2
  fund_zat="$((AMOUNT_B_ZAT + 20000000))"
  fund_str="$(zat_to_junocash_amount "${fund_zat}")"
  recipients_fund="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${SOLVER_B_UA}" "${fund_str}")"
  opid_fund="$(jcli z_sendmany "${USER_UA}" "${recipients_fund}" "${JUNOCASH_SEND_MINCONF}" | parse_junocash_opid)"
  txid_fund="$(wait_for_op_txid "${opid_fund}" 1800)"
  echo "txid_fund_b=${txid_fund}" >&2
  if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
    echo "mining block to include funding tx (B)..." >&2
    jcli generate 1 >/dev/null
  else
    echo "mining block to include funding tx (B)..." >&2
    scripts/junocash/testnet/mine.sh 1 >/dev/null
    fund_height_b="$(wait_for_tx_confirmations "${txid_fund}" 1 600)"
    echo "fund_height_b=${fund_height_b}" >&2
  fi

  echo "waiting for solver B orchard note to become spendable..." >&2
  FUND_ACTION_B=""
  for _ in $(seq 1 1800); do
    FUND_ACTION_B="$(jcli z_listunspent 1 9999999 false | python3 -c 'import json,sys
txid=sys.argv[1].strip().lower()
acct=int(sys.argv[2])
notes=json.load(sys.stdin)
for n in notes:
  if str(n.get("pool",""))!="orchard":
    continue
  if str(n.get("txid","")).strip().lower()!=txid:
    continue
  if n.get("account")!=acct:
    continue
  if not n.get("spendable"):
    continue
  print(n.get("outindex"))
  sys.exit(0)
sys.exit(1)
' "${txid_fund}" "${SOLVER_B_ACCOUNT}")" && break || true
    sleep 1
  done
  if [[ -z "${FUND_ACTION_B}" ]]; then
    echo "solver B funding note did not become spendable" >&2
    exit 1
  fi
fi

echo "sending JunoCash payment solver->user (amount=${PAYMENT_AMOUNT_B_STR})..." >&2
recipients_b="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${USER_UA}" "${PAYMENT_AMOUNT_B_STR}")"
opid_b="$(jcli z_sendmany "${SOLVER_B_UA}" "${recipients_b}" "${JUNOCASH_SEND_MINCONF}" | parse_junocash_opid)"

echo "waiting for sendmany operation (B)..." >&2
txid_b="$(wait_for_op_txid "${opid_b}" 1800)"
echo "txid_b=${txid_b}" >&2

height_b_before="$(jcli getblockcount)"
if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
  echo "mining block to include payment tx (B)..." >&2
  jcli generate 1 >/dev/null
  height_b_after="$(jcli getblockcount)"
  PAYMENT_HEIGHT_B="${height_b_after}"
  echo "payment_height_b=${PAYMENT_HEIGHT_B} (before=${height_b_before} after=${height_b_after})" >&2
else
  echo "mining block to include payment tx (B)..." >&2
  scripts/junocash/testnet/mine.sh 1 >/dev/null
  PAYMENT_HEIGHT_B="$(wait_for_tx_confirmations "${txid_b}" 1 600)"
  echo "payment_height_b=${PAYMENT_HEIGHT_B} (before=${height_b_before})" >&2
fi

echo "waiting for user orchard note to appear (B)..." >&2
ACTION_B=""
for _ in $(seq 1 1800); do
  ACTION_B="$(jcli z_listunspent 1 9999999 false | python3 -c 'import json,sys
txid=sys.argv[1].strip().lower()
acct=int(sys.argv[2])
notes=json.load(sys.stdin)
for n in notes:
  if str(n.get("pool",""))!="orchard":
    continue
  if str(n.get("txid","")).strip().lower()!=txid:
    continue
  if n.get("account")!=acct:
    continue
  if not n.get("spendable"):
    continue
  print(n.get("outindex"))
  sys.exit(0)
sys.exit(1)
' "${txid_b}" "${USER_ACCOUNT}")" && break || true
  sleep 1
done
if [[ -z "${ACTION_B}" ]]; then
  echo "failed to find user note outindex for tx B" >&2
  exit 1
fi
echo "action_b=${ACTION_B}" >&2

echo "generating receipt witness (B, outgoing via solver ovk)..." >&2
WITNESS_B="$(cd "${ROOT}" && cargo run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli "${JUNOCASH_CLI}" \
  --wallet "${WALLET_DAT}" \
  --txid "${txid_b}" \
  --action "${ACTION_B}" \
  --unified-address "${SOLVER_B_UA}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_B}")"

INPUTS_B="$("${GO_INTENTS}" receipt-inputs --witness-hex "${WITNESS_B}" --json=false)"
AMOUNT_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^amount=([0-9]+)$/\1/p' | head -n 1)"
RECEIVER_TAG_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^receiver_tag=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
ORCHARD_ROOT_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^orchard_root=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
if [[ -n "${AMOUNT_B_ZAT:-}" && "${AMOUNT_B}" != "${AMOUNT_B_ZAT}" ]]; then
  echo "quote/witness amount mismatch (B): quote=${AMOUNT_B_ZAT} witness=${AMOUNT_B}" >&2
  exit 1
fi
echo "orchard_root_b=${ORCHARD_ROOT_B}" >&2
echo "receiver_tag_b=${RECEIVER_TAG_B}" >&2
echo "junocash_amount_b_zat=${AMOUNT_B}" >&2

echo "waiting for +1 confirmation (reorg safety)..." >&2
if [[ "${JUNOCASH_CHAIN}" == "regtest" ]]; then
  jcli generate 1 >/dev/null
else
  scripts/junocash/testnet/mine.sh 1 >/dev/null
  wait_for_tx_confirmations "${txid_b}" 2 600 >/dev/null
fi

echo "finalizing CRP checkpoints (run-mode, chain verified)..." >&2
genesis="$(jcli getblockhash 0 | tr -d '\" \r\n')"
chain="$(jcli getblockchaininfo | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chain",""))')"
chain_norm="$(printf '%s' "${chain}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n' | sed -E 's/^main$/mainnet/; s/^test$/testnet/')"
genesis_norm="$(printf '%s' "${genesis}" | tr '[:upper:]' '[:lower:]' | tr -d '\" \t\r\n' | sed -E 's/^0x//')"
expected_chain_norm="$(printf '%s' "${JUNOCASH_CHAIN}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n')"
expected_genesis_norm="$(printf '%s' "${JUNOCASH_GENESIS_EXPECTED}" | tr '[:upper:]' '[:lower:]' | tr -d '\" \t\r\n' | sed -E 's/^0x//')"
echo "junocash_chain=${chain_norm}" >&2
echo "junocash_genesis=${genesis_norm}" >&2
if [[ "${chain_norm}" != "${expected_chain_norm}" ]]; then
  echo "junocash chain mismatch: got ${chain_norm} want ${expected_chain_norm}" >&2
  exit 1
fi
if [[ "${genesis_norm}" != "${expected_genesis_norm}" ]]; then
  echo "junocash genesis mismatch: got ${genesis_norm} want ${expected_genesis_norm}" >&2
  exit 1
fi

start_height="${PAYMENT_HEIGHT_A}"
if [[ "${PAYMENT_HEIGHT_B}" -lt "${start_height}" ]]; then
  start_height="${PAYMENT_HEIGHT_B}"
fi

if [[ -n "${CRP_SUBMIT_ENCLAVE_CID1}" && -n "${CRP_SUBMIT_ENCLAVE_CID2}" ]]; then
  echo "CRP submit: signing via Nitro enclaves (CIDs ${CRP_SUBMIT_ENCLAVE_CID1}, ${CRP_SUBMIT_ENCLAVE_CID2})..." >&2
  for cid in "${CRP_SUBMIT_ENCLAVE_CID1}" "${CRP_SUBMIT_ENCLAVE_CID2}"; do
    "${GO_CRP}" run \
      --deployment "${DEPLOYMENT_NAME}" \
      --deployment-file "${DEPLOYMENT_FILE}" \
      --junocash-cli "${JUNOCASH_CLI}" \
      --junocash-chain "${JUNOCASH_CHAIN}" \
      --junocash-genesis-hash "${JUNOCASH_GENESIS_EXPECTED}" \
      --start-height "${start_height}" \
      --lag 1 \
      --poll-interval 1s \
      --payer-keypair "${SOLVER_KEYPAIR}" \
      --submit-operator-enclave-cid "${cid}" \
      --submit-operator-enclave-port "${CRP_SUBMIT_ENCLAVE_PORT}" \
      --priority-level "${PRIORITY_LEVEL}" \
      --once --submit-only >/dev/null
  done
  echo "CRP finalize: finalize-pending (extract signatures from chain)..." >&2
  "${GO_CRP}" finalize-pending \
    --deployment "${DEPLOYMENT_NAME}" \
    --deployment-file "${DEPLOYMENT_FILE}" \
    --payer-keypair "${SOLVER_KEYPAIR}" \
    --config-scan-limit 200 \
    --scan-limit 300 \
    --max-checkpoints 100 \
    --priority-level "${PRIORITY_LEVEL}" >/dev/null
else
  "${GO_CRP}" run \
    --deployment "${DEPLOYMENT_NAME}" \
    --deployment-file "${DEPLOYMENT_FILE}" \
    --junocash-cli "${JUNOCASH_CLI}" \
    --junocash-chain "${JUNOCASH_CHAIN}" \
    --junocash-genesis-hash "${JUNOCASH_GENESIS_EXPECTED}" \
    --start-height "${start_height}" \
    --lag 1 \
    --poll-interval 1s \
    --payer-keypair "${SOLVER_KEYPAIR}" \
    --submit-operator-keypair "${OP1_KEYPAIR}" \
    --finalize-operator-keypair "${OP1_KEYPAIR}" \
    --finalize-operator-keypair "${OP2_KEYPAIR}" \
    --priority-level "${PRIORITY_LEVEL}" \
    --once >/dev/null
fi

echo "filling intents on Solana..." >&2
"${GO_INTENTS}" iep-fill \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --intent "${INTENT_A}" \
  --mint "${MINT}" \
  --receiver-tag "${RECEIVER_TAG_A}" \
  --junocash-amount "${AMOUNT_A}" \
  --solver-keypair "${SOLVER_A_KEYPAIR}" \
  --solver-source-token-account "${SOLVER_A_TA}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

"${GO_INTENTS}" iep-fill \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --intent "${INTENT_B}" \
  --mint "${MINT}" \
  --receiver-tag "${RECEIVER_TAG_B}" \
  --junocash-amount "${AMOUNT_B}" \
  --solver-keypair "${SOLVER_B_KEYPAIR}" \
  --solver-destination-token-account "${SOLVER_B_TA}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

echo "proving Groth16 bundles (CUDA)..." >&2
RAW_BUNDLE_A="$(cd "${ROOT}" && cargo run --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --bin prove_bundle_v1 -- --witness-hex "${WITNESS_A}")"
BUNDLE_A="$(printf '%s\n' "${RAW_BUNDLE_A}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1 || true)"
if [[ -z "${BUNDLE_A}" ]]; then
  echo "failed to extract bundle hex (A)" >&2
  printf '%s\n' "${RAW_BUNDLE_A}" | head -n 50 >&2 || true
  exit 1
fi

RAW_BUNDLE_B="$(cd "${ROOT}" && cargo run --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --bin prove_bundle_v1 -- --witness-hex "${WITNESS_B}")"
BUNDLE_B="$(printf '%s\n' "${RAW_BUNDLE_B}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1 || true)"
if [[ -z "${BUNDLE_B}" ]]; then
  echo "failed to extract bundle hex (B)" >&2
  printf '%s\n' "${RAW_BUNDLE_B}" | head -n 50 >&2 || true
  exit 1
fi

echo "settling on Solana..." >&2
"${GO_INTENTS}" iep-settle \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --intent "${INTENT_A}" \
  --mint "${MINT}" \
  --recipient-token-account "${CREATOR_TA}" \
  --fee-token-account "${FEE_TA}" \
  --bundle-hex "${BUNDLE_A}" \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

"${GO_INTENTS}" iep-settle \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --intent "${INTENT_B}" \
  --mint "${MINT}" \
  --recipient-token-account "${SOLVER_B_TA}" \
  --fee-token-account "${FEE_TA}" \
  --bundle-hex "${BUNDLE_B}" \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

spl_balance_amount() {
  local token_account="$1"
  local out
  if ! out="$(spl-token -u "${SOLANA_RPC_URL}" balance --address "${token_account}" --output json-compact 2>&1)"; then
    echo "spl-token balance failed for ${token_account}" >&2
    printf '%s\n' "${out}" >&2
    return 1
  fi
  python3 -c 'import json,sys
token_account=sys.argv[1]
raw=sys.stdin.read().strip()
if not raw:
  raise SystemExit(f"empty spl-token balance output for {token_account}")
try:
  obj=json.loads(raw)
except Exception:
  raise SystemExit(f"invalid spl-token balance json for {token_account}: {raw}")
amt=obj.get("amount")
if amt is None:
  raise SystemExit(f"missing amount in balance output for {token_account}: {raw}")
print(str(amt))
' "${token_account}" <<<"${out}"
}

set_stage "verify_balances"
echo "verifying balances..." >&2
creator_balance="$(spl_balance_amount "${CREATOR_TA}")"
solver_balance="$(spl_balance_amount "${SOLVER_TA}")"
solver2_balance="$(spl_balance_amount "${SOLVER2_TA}")"
fee_balance="$(spl_balance_amount "${FEE_TA}")"
for name in creator_balance solver_balance solver2_balance fee_balance; do
  val="${!name:-}"
  if [[ ! "${val}" =~ ^[0-9]+$ ]]; then
    echo "invalid ${name}: ${val}" >&2
    exit 1
  fi
done
echo "creator_balance=${creator_balance}" >&2
echo "solver_balance=${solver_balance}" >&2
echo "solver2_balance=${solver2_balance}" >&2
echo "fee_balance=${fee_balance}" >&2

set_stage "crp_report"
echo "producing CRP checkpoint report..." >&2
CRP_REPORT_PATH="${WORKDIR}/crp-monitor-report.json"
for i in $(seq 1 3); do
  if "${GO_CRP_MONITOR}" check \
    --deployment "${DEPLOYMENT_NAME}" \
    --deployments "${DEPLOYMENT_FILE}" \
    --rpc-url "${SOLANA_RPC_URL}" \
    --junocash-cli "${JUNOCASH_CLI}" \
    --max-lag 20 >"${CRP_REPORT_PATH}"; then
    break
  fi
  echo "crp-monitor attempt ${i} failed; retrying..." >&2
  sleep "$((i * 5))"
done
if [[ ! -s "${CRP_REPORT_PATH}" ]]; then
  echo "crp-monitor report missing/empty: ${CRP_REPORT_PATH}" >&2
  exit 1
fi
echo "crp_monitor_report=${CRP_REPORT_PATH}" >&2
if [[ -n "${E2E_ARTIFACT_DIR}" ]]; then
  mkdir -p "${E2E_ARTIFACT_DIR}"
  cp "${CRP_REPORT_PATH}" "${E2E_ARTIFACT_DIR}/crp-monitor-report.json"
  echo "crp_monitor_report_artifact=${E2E_ARTIFACT_DIR}/crp-monitor-report.json" >&2
fi

set_stage "complete"
echo "e2e ok" >&2
