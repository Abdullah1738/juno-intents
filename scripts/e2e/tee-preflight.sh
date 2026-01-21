#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENT_FILE="deployments.json"
BASE_DEPLOYMENT=""

E2E_ARTIFACT_DIR="${JUNO_E2E_ARTIFACT_DIR:-}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/e2e/tee-preflight.sh --base-deployment <name> [--deployment-file <path>]

Notes:
  - Fast, non-proving preflight for CRP v2 + Nitro Enclaves hosts.
  - Checks funded devnet keypairs, builds EIF, and smoke-tests enclave startup + witness generation.
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
need_cmd solana
need_cmd solana-keygen
need_cmd docker

NITRO_CLI="nitro-cli"
if [[ -x "/opt/nitro-cli/usr/bin/nitro-cli" ]]; then
  NITRO_CLI="/opt/nitro-cli/usr/bin/nitro-cli"
else
  need_cmd nitro-cli
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
emit("JUNOCASH_CHAIN", entry.get("junocash_chain"))
emit("JUNOCASH_GENESIS_HASH", entry.get("junocash_genesis_hash"))
PY
)"

while IFS='=' read -r k v; do
  export "${k}=${v}"
done <<<"${BASE_ENV}"

if [[ -z "${RPC_URL:-}" || -z "${JUNOCASH_CHAIN:-}" || -z "${JUNOCASH_GENESIS_HASH:-}" ]]; then
  echo "base deployment missing required fields (rpc_url/junocash_chain/junocash_genesis_hash)" >&2
  printf '%s\n' "${BASE_ENV}" >&2
  exit 1
fi

case "$(printf '%s' "${JUNOCASH_CHAIN}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n')" in
  mainnet) CHAIN_ID=1 ;;
  testnet) CHAIN_ID=2 ;;
  regtest) CHAIN_ID=3 ;;
  *) echo "unsupported junocash_chain: ${JUNOCASH_CHAIN}" >&2; exit 1 ;;
esac

ts="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="${ROOT}/tmp/e2e/tee-preflight/${ts}"
mkdir -p "${WORKDIR}"

cleanup() {
  scripts/junocash/testnet/down.sh >/dev/null 2>&1 || true
  scripts/junocash/regtest/down.sh >/dev/null 2>&1 || true
  sudo "${NITRO_CLI}" terminate-enclave --all >/dev/null 2>&1 || true
}
trap cleanup EXIT

SOLVER_KEYPAIR="${JUNO_E2E_SOLVER_KEYPAIR:-}"
CREATOR_KEYPAIR="${JUNO_E2E_CREATOR_KEYPAIR:-}"
if [[ -z "${SOLVER_KEYPAIR}" || -z "${CREATOR_KEYPAIR}" ]]; then
  echo "JUNO_E2E_SOLVER_KEYPAIR and JUNO_E2E_CREATOR_KEYPAIR are required (paths to funded Solana CLI JSON keypairs)" >&2
  exit 2
fi
if [[ ! -f "${SOLVER_KEYPAIR}" ]]; then
  echo "solver keypair not found: ${SOLVER_KEYPAIR}" >&2
  exit 2
fi
if [[ ! -f "${CREATOR_KEYPAIR}" ]]; then
  echo "creator keypair not found: ${CREATOR_KEYPAIR}" >&2
  exit 2
fi

SOLVER_PUBKEY="$(solana-keygen pubkey "${SOLVER_KEYPAIR}")"
CREATOR_PUBKEY="$(solana-keygen pubkey "${CREATOR_KEYPAIR}")"

balance_lamports() {
  local pubkey="$1"
  local raw out
  for i in $(seq 1 10); do
    raw="$(solana -u "${RPC_URL}" balance "${pubkey}" --lamports 2>&1 || true)"
    out="$(
      python3 -c 'import re,sys
raw=sys.stdin.read()
m=re.search(r"(\d+)\s*lamports\b", raw)
print(m.group(1) if m else "")
' <<<"${raw}"
    )"
    if [[ "${out}" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "${out}"
      return 0
    fi
    sleep "${i}"
  done
  echo "failed to fetch solana balance (pubkey=${pubkey})" >&2
  echo "${raw:-}" >&2
  return 1
}

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

min_solver_lamports="${JUNO_E2E_MIN_SOLVER_LAMPORTS:-3000000000}"   # 3 SOL
min_creator_lamports="${JUNO_E2E_MIN_CREATOR_LAMPORTS:-500000000}" # 0.5 SOL

creator_bal=""
if ! solver_bal="$(balance_lamports "${SOLVER_PUBKEY}")"; then
  exit 1
fi
if ! creator_bal="$(balance_lamports "${CREATOR_PUBKEY}")"; then
  exit 1
fi
if [[ ! "${solver_bal}" =~ ^[0-9]+$ || "${solver_bal}" -lt "${min_solver_lamports}" ]]; then
  echo "solver needs funding (pubkey=${SOLVER_PUBKEY} lamports=${solver_bal:-unknown} min=${min_solver_lamports})" >&2
  echo "attempting solana devnet airdrop top-up..." >&2
  topup_sol="${JUNO_E2E_SOLVER_TOPUP_SOL:-1}"
  airdrop "${SOLVER_PUBKEY}" "${topup_sol}" "${SOLVER_KEYPAIR}" || true
  if ! solver_bal="$(balance_lamports "${SOLVER_PUBKEY}")"; then
    exit 1
  fi
  if [[ ! "${solver_bal}" =~ ^[0-9]+$ || "${solver_bal}" -lt "${min_solver_lamports}" ]]; then
    echo "solver still needs funding (pubkey=${SOLVER_PUBKEY} lamports=${solver_bal:-unknown} min=${min_solver_lamports})" >&2
    exit 1
  fi
fi
if [[ "${creator_bal}" -lt "${min_creator_lamports}" ]]; then
  echo "funding creator from solver..." >&2
  for i in $(seq 1 10); do
    if solana -u "${RPC_URL}" transfer --allow-unfunded-recipient -k "${SOLVER_KEYPAIR}" "${CREATOR_PUBKEY}" 1 >/dev/null 2>&1; then
      break
    fi
    sleep "${i}"
  done
  if ! creator_bal="$(balance_lamports "${CREATOR_PUBKEY}")"; then
    exit 1
  fi
  if [[ ! "${creator_bal}" =~ ^[0-9]+$ || "${creator_bal}" -lt "${min_creator_lamports}" ]]; then
    echo "creator still needs funding (pubkey=${CREATOR_PUBKEY} lamports=${creator_bal:-unknown} min=${min_creator_lamports})" >&2
    exit 1
  fi
fi

echo "junocash preflight..." >&2
JUNOCASH_PREFLIGHT_HEIGHT=""
case "$(printf '%s' "${JUNOCASH_CHAIN}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n')" in
  regtest)
    scripts/junocash/regtest/up.sh >/dev/null
    JUNOCASH_PREFLIGHT_HEIGHT="$(scripts/junocash/regtest/cli.sh getblockcount)"
    scripts/junocash/regtest/cli.sh generate 1 >/dev/null
    ;;
  testnet)
    if [[ -z "${JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64:-}" ]]; then
      echo "JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64 is required for testnet preflight" >&2
      exit 2
    fi

    echo "validating testnet wallet.dat (no sync/mining)..." >&2
    export JUNO_TESTNET_DATA_DIR_A="${WORKDIR}/junocash-testnet-a"
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

    JUNOCASH_ROOT="$(scripts/junocash/fetch-linux64.sh)"
    "${JUNOCASH_ROOT}/bin/junocashd" \
      -testnet \
      -datadir="${JUNO_TESTNET_DATA_DIR_A}" \
      -server=1 \
      -printtoconsole=0 \
      -listen=0 \
      -dnsseed=0 \
      -maxconnections=1 \
      -rpcworkqueue=16 \
      -rpcclienttimeout=30 \
      -daemon >/dev/null 2>&1

    for _ in $(seq 1 30); do
      if "${JUNOCASH_ROOT}/bin/junocash-cli" -testnet -datadir="${JUNO_TESTNET_DATA_DIR_A}" getblockcount >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done

    accounts="$("${JUNOCASH_ROOT}/bin/junocash-cli" -testnet -datadir="${JUNO_TESTNET_DATA_DIR_A}" z_listaccounts 2>/dev/null || true)"
    python3 - <<'PY' <<<"${accounts}"
import json,sys
raw=sys.stdin.read()
try:
  acc=json.loads(raw)
except Exception:
  raise SystemExit("z_listaccounts did not return JSON")
if not isinstance(acc, list) or not acc:
  raise SystemExit("z_listaccounts returned no accounts")
addrs=((acc[0] or {}).get("addresses") or [])
if not addrs:
  raise SystemExit("account 0 has no addresses")
ua=((addrs[0] or {}).get("ua") or "").strip()
if not ua.startswith("jtest"):
  raise SystemExit(f"unexpected ua: {ua}")
print(f"wallet_ok ua={ua}")
PY
    JUNOCASH_PREFLIGHT_HEIGHT="$("${JUNOCASH_ROOT}/bin/junocash-cli" -testnet -datadir="${JUNO_TESTNET_DATA_DIR_A}" getblockcount 2>/dev/null || true)"
    "${JUNOCASH_ROOT}/bin/junocash-cli" -testnet -datadir="${JUNO_TESTNET_DATA_DIR_A}" stop >/dev/null 2>&1 || true
    ;;
  *)
    echo "unsupported junocash_chain: ${JUNOCASH_CHAIN}" >&2
    exit 1
    ;;
esac
if [[ -z "${JUNOCASH_PREFLIGHT_HEIGHT}" || ! "${JUNOCASH_PREFLIGHT_HEIGHT}" =~ ^[0-9]+$ ]]; then
  echo "failed to determine junocash height during preflight" >&2
  exit 1
fi
if [[ "$(printf '%s' "${JUNOCASH_CHAIN}" | tr '[:upper:]' '[:lower:]' | tr -d ' \t\r\n')" != "testnet" && "${JUNOCASH_PREFLIGHT_HEIGHT}" -lt 1 ]]; then
  echo "junocash preflight failed (height=${JUNOCASH_PREFLIGHT_HEIGHT})" >&2
  exit 1
fi
echo "junocash preflight ok (height=${JUNOCASH_PREFLIGHT_HEIGHT})" >&2

echo "preparing nitro log dir..." >&2
sudo mkdir -p /var/log/nitro_enclaves
sudo touch /var/log/nitro_enclaves/nitro_enclaves.log
sudo chown root:root /var/log/nitro_enclaves /var/log/nitro_enclaves/nitro_enclaves.log || true
sudo chmod 755 /var/log/nitro_enclaves || true
sudo chmod 644 /var/log/nitro_enclaves/nitro_enclaves.log || true
sudo mkdir -p /run/nitro_enclaves
sudo chown root:root /run/nitro_enclaves || true
sudo chmod 775 /run/nitro_enclaves || true

echo "building EIF (preflight)..." >&2
eif_out="${WORKDIR}/build-eif.stdout.log"
eif_err="${WORKDIR}/build-eif.stderr.log"
if ! JUNO_EIF_DOCKERFILE=enclave/operator/Dockerfile.e2e \
  JUNO_EIF_OUT_DIR="${WORKDIR}/eif" \
  JUNO_EIF_OUT_EIF="${WORKDIR}/eif/operator.eif" \
  "${ROOT}/scripts/enclave/build-eif.sh" >"${eif_out}" 2>"${eif_err}"; then
  echo "EIF build failed (tailing logs)..." >&2
  tail -n 80 "${eif_out}" >&2 || true
  tail -n 80 "${eif_err}" >&2 || true
  exit 1
fi
EIF_PCR0="$(sed -nE 's/^pcr0=([0-9a-fA-F]{96})$/\1/p' "${eif_err}" | tail -n 1 || true)"
EIF_SHA256="$(sed -nE 's/^eif_sha256=([0-9a-fA-F]{64})$/\1/p' "${eif_err}" | tail -n 1 || true)"
if [[ -z "${EIF_PCR0}" || ! "${EIF_PCR0}" =~ ^[0-9a-fA-F]{96}$ ]]; then
  echo "failed to parse eif pcr0" >&2
  tail -n 80 "${eif_err}" >&2 || true
  exit 1
fi
if [[ -z "${EIF_SHA256}" || ! "${EIF_SHA256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "failed to parse eif sha256" >&2
  tail -n 80 "${eif_err}" >&2 || true
  exit 1
fi

echo "starting enclave (preflight)..." >&2
CID=16
PORT=5000
if ! sudo "${NITRO_CLI}" run-enclave --eif-path "${WORKDIR}/eif/operator.eif" --cpu-count 2 --memory 1024 --enclave-cid "${CID}" >/dev/null; then
  echo "failed to run enclave" >&2
  sudo "${NITRO_CLI}" describe-enclaves >&2 || true
  exit 1
fi

need_cmd go
(cd "${ROOT}" && go build -o "${WORKDIR}/nitro-operator" ./cmd/nitro-operator)
DEPLOYMENT_ID="$(openssl rand -hex 32)"
witness="$(sudo -E "${WORKDIR}/nitro-operator" witness --enclave-cid "${CID}" --enclave-port "${PORT}" --deployment-id "${DEPLOYMENT_ID}" --junocash-chain-id "${CHAIN_ID}" --junocash-genesis-hash "${JUNOCASH_GENESIS_HASH}")"
witness_sha256="$(python3 - <<PY
import binascii,hashlib
data=binascii.unhexlify("${witness}")
print(hashlib.sha256(data).hexdigest())
PY
)"

SUMMARY_PATH="${WORKDIR}/tee-preflight-summary.json"
python3 - <<PY
import json,time
out = {
  "stage": "tee_preflight_ok",
  "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
  "base_deployment": "${BASE_DEPLOYMENT}",
  "solana": {
    "rpc_url": "${RPC_URL}",
    "solver_pubkey": "${SOLVER_PUBKEY}",
    "creator_pubkey": "${CREATOR_PUBKEY}",
    "solver_balance_lamports": int("${solver_bal}"),
    "creator_balance_lamports": int("${creator_bal}"),
  },
  "junocash": {
    "chain": "${JUNOCASH_CHAIN}",
    "chain_id": int("${CHAIN_ID}"),
    "genesis_hash": "${JUNOCASH_GENESIS_HASH}",
    "height_preflight": int("${JUNOCASH_PREFLIGHT_HEIGHT}"),
  },
  "tee": {
    "eif_pcr0": "${EIF_PCR0}",
    "eif_sha256": "${EIF_SHA256}",
    "enclave_cid": int("${CID}"),
    "witness_sha256": "${witness_sha256}",
  },
}
with open("${SUMMARY_PATH}", "w", encoding="utf-8") as f:
  json.dump(out, f, indent=2, sort_keys=True)
  f.write("\\n")
PY

echo "tee_preflight_summary=${SUMMARY_PATH}" >&2
if [[ -n "${E2E_ARTIFACT_DIR}" ]]; then
  mkdir -p "${E2E_ARTIFACT_DIR}"
  cp "${SUMMARY_PATH}" "${E2E_ARTIFACT_DIR}/tee-preflight-summary.json"
  echo "tee_preflight_summary_artifact=${E2E_ARTIFACT_DIR}/tee-preflight-summary.json" >&2
fi

echo "tee preflight ok" >&2
