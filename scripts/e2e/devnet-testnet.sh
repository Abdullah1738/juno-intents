#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENTS_FILE="deployments.json"
BASE_DEPLOYMENT=""
WORKDIR_OVERRIDE=""
RPC_URL_OVERRIDE=""

NET_AMOUNT_A="${JUNO_E2E_NET_AMOUNT_A:-1000}"
NET_AMOUNT_B="${JUNO_E2E_NET_AMOUNT_B:-1000}"
JUNOCASH_SEND_MINCONF="${JUNO_E2E_JUNOCASH_SEND_MINCONF:-10}"
JUNOCASH_TESTNET_WALLET_DAT_GZ_B64="${JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64:-}"
JUNOCASH_TESTNET_PREFUND_AMOUNT="${JUNO_E2E_JUNOCASH_TESTNET_PREFUND_AMOUNT:-5.0}"
JUNOCASH_TESTNET_FUND_TIMEOUT_SECS="${JUNO_E2E_JUNOCASH_TESTNET_FUND_TIMEOUT_SECS:-3600}"
JUNOCASH_TESTNET_MODE="${JUNO_E2E_JUNOCASH_TESTNET_MODE:-${JUNO_TESTNET_MODE:-public}}"

PRIORITY_LEVEL="${JUNO_E2E_PRIORITY_LEVEL:-Medium}"

# If explicitly set (even empty), honor it.
# Otherwise: default to CUDA only when proving on-host.
if [[ -n "${JUNO_E2E_RISC0_FEATURES+set}" ]]; then
  RISC0_FEATURES="${JUNO_E2E_RISC0_FEATURES}"
elif [[ "${JUNO_RISC0_USE_DOCKER:-0}" == "1" ]]; then
  RISC0_FEATURES=""
else
  RISC0_FEATURES="cuda"
fi

risc0_prove_bundle() {
  local manifest="$1"
  local bin="$2"
  local witness_hex="$3"

  local witness_env="JUNO_RECEIPT_WITNESS_HEX"
  if [[ "${bin}" == *attestation* ]]; then
    witness_env="JUNO_ATTESTATION_WITNESS_HEX"
  fi

  if [[ -n "${RISC0_FEATURES}" ]]; then
    (
      cd "${ROOT}" && \
      export "${witness_env}=${witness_hex}" && \
      cargo run --release --locked --manifest-path "${manifest}" --features "${RISC0_FEATURES}" --bin "${bin}"
    )
  else
    (
      cd "${ROOT}" && \
      export "${witness_env}=${witness_hex}" && \
      cargo run --release --locked --manifest-path "${manifest}" --bin "${bin}"
    )
  fi
}

SOLVER_KEYPAIR_OVERRIDE="${JUNO_E2E_SOLVER_KEYPAIR:-}"
SOLVER2_KEYPAIR_OVERRIDE="${JUNO_E2E_SOLVER2_KEYPAIR:-}"
CREATOR_KEYPAIR_OVERRIDE="${JUNO_E2E_CREATOR_KEYPAIR:-}"
SOLANA_FUNDER_KEYPAIR="${JUNO_E2E_SOLANA_FUNDER_KEYPAIR:-}"

NITRO_CID1="${JUNO_E2E_NITRO_CID1:-${JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1:-}}"
NITRO_CID2="${JUNO_E2E_NITRO_CID2:-${JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID2:-}}"
NITRO_PORT="${JUNO_E2E_NITRO_PORT:-${JUNO_E2E_CRP_SUBMIT_ENCLAVE_PORT:-5000}}"

FEE_COLLECTOR_PUBKEY="7Qx1LJUMeCXr8ygfwdnEmGbYSsQPrgHrFU7VPuGXJeEH"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/e2e/devnet-testnet.sh --base-deployment <name> [--deployments-file <path>] [--rpc-url <url>] [--workdir <path>]

This is a real-network E2E that targets:
  - Solana devnet
  - JunoCash testnet (via scripts/junocash/testnet/* Docker harness)

It creates a fresh deployment_id and initializes:
  - ORP (Operator Registry) + registers two Nitro-attested operators (Groth16 on-chain verification)
  - CRP (Checkpoint Registry v2, bound to ORP)
  - IEP (Intent Escrow v3, bound to a single wJUNO SPL mint)

Then it runs:
  - Two solvernet solvers (auto-fill) competing on RFQ
  - Direction A: JunoCash -> wJUNO
  - Direction B: wJUNO -> JunoCash

Required environment:
  - Two running Nitro operator enclaves:
      JUNO_E2E_NITRO_CID1 / JUNO_E2E_NITRO_CID2  (or legacy: JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1/2)
      JUNO_E2E_NITRO_PORT (default: 5000)

JunoCash testnet funding (choose ONE):
  - JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64  base64(gzip(wallet.dat)) of a prefunded testnet wallet (recommended)
  - Or: run without a prefunded wallet; the script prints a fresh Orchard UA and waits for it to be funded (default: 5.0; override via JUNO_E2E_JUNOCASH_TESTNET_PREFUND_AMOUNT).

Optional environment:
  - JUNO_E2E_JUNOCASH_TESTNET_MODE (default: public; set to pair for a 2-node private testnet)
  - JUNO_E2E_NET_AMOUNT_A / JUNO_E2E_NET_AMOUNT_B (default: 1000)
  - JUNO_E2E_PRIORITY_LEVEL (default: Medium)
  - JUNO_E2E_RISC0_FEATURES (default: cuda; set to empty to disable CUDA and use Docker proving)
  - JUNO_E2E_SOLANA_FUNDER_KEYPAIR (funded devnet keypair used to fund solver/creator when airdrops are rate-limited)
  - JUNO_E2E_SOLVER_KEYPAIR / _SOLVER2_KEYPAIR / _CREATOR_KEYPAIR (skip airdrop if provided)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --base-deployment) BASE_DEPLOYMENT="${2:-}"; shift 2 ;;
    --deployments-file) DEPLOYMENTS_FILE="${2:-}"; shift 2 ;;
    --rpc-url) RPC_URL_OVERRIDE="${2:-}"; shift 2 ;;
    --workdir) WORKDIR_OVERRIDE="${2:-}"; shift 2 ;;
    *) echo "unexpected argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${BASE_DEPLOYMENT}" ]]; then
  echo "--base-deployment is required" >&2
  exit 2
fi
if [[ ! -f "${DEPLOYMENTS_FILE}" ]]; then
  echo "deployments file not found: ${DEPLOYMENTS_FILE}" >&2
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

# Prefer a modern GCC on Amazon Linux 2; older libstdc++ lacks some C++17
# algorithms (e.g. inclusive_scan/exclusive_scan) used by RISC0 native kernels.
if [[ -z "${CC:-}" ]]; then
  if command -v gcc10-gcc >/dev/null; then
    CC="gcc10-gcc"
  elif command -v gcc-10 >/dev/null; then
    CC="gcc-10"
  fi
fi
if [[ -z "${CXX:-}" ]]; then
  if command -v gcc10-g++ >/dev/null; then
    CXX="gcc10-g++"
  elif command -v g++-10 >/dev/null; then
    CXX="g++-10"
  fi
fi
export CC CXX

if [[ -n "${RISC0_FEATURES}" && "${RISC0_FEATURES}" == *cuda* ]]; then
  if command -v nvcc >/dev/null; then
    NVCC="${NVCC:-$(command -v nvcc)}"
    export NVCC
  fi

  if [[ -z "${NVCC_APPEND_FLAGS:-}" ]]; then
    NVCC_APPEND_FLAGS="-DNDEBUG"
    export NVCC_APPEND_FLAGS
  fi

  if [[ -z "${NVCC_PREPEND_FLAGS:-}" ]] && command -v nvidia-smi >/dev/null; then
    ccap="$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -n 1 | tr -d ' \t\r\n' || true)"
    if [[ "${ccap}" =~ ^[0-9]+\\.[0-9]+$ ]]; then
      major="${ccap%.*}"
      minor="${ccap#*.}"
      NVCC_PREPEND_FLAGS="-arch=sm_${major}${minor}"
      export NVCC_PREPEND_FLAGS
    fi
  fi

  # If we set NVCC_APPEND_FLAGS but leave NVCC_PREPEND_FLAGS unset, some RISC0 CUDA
  # build scripts will not add an arch flag and nvcc defaults to sm_52, which is
  # too old for CUDA atomics. Ensure a sane default.
  if [[ -z "${NVCC_PREPEND_FLAGS:-}" ]]; then
    NVCC_PREPEND_FLAGS="-arch=native"
    export NVCC_PREPEND_FLAGS
  fi
fi

retry() {
  local attempts="${1:-5}"
  local delay_secs="${2:-3}"
  shift 2

  local n=1
  while true; do
    if "$@"; then
      return 0
    fi
    if (( n >= attempts )); then
      echo "command failed after ${attempts} attempts: $*" >&2
      return 1
    fi
    echo "command failed; retrying in ${delay_secs}s (${n}/${attempts}): $*" >&2
    sleep "${delay_secs}"
    n="$((n + 1))"
  done
}

if [[ -z "${NITRO_CID1}" || -z "${NITRO_CID2}" ]]; then
  echo "missing Nitro enclave CIDs: set JUNO_E2E_NITRO_CID1 and JUNO_E2E_NITRO_CID2 (or legacy JUNO_E2E_CRP_SUBMIT_ENCLAVE_CID1/2)" >&2
  exit 2
fi
if [[ ! "${NITRO_CID1}" =~ ^[0-9]+$ || ! "${NITRO_CID2}" =~ ^[0-9]+$ ]]; then
  echo "Nitro enclave CIDs must be u32 integers" >&2
  exit 2
fi
if [[ ! "${NITRO_PORT}" =~ ^[0-9]+$ || "${NITRO_PORT}" -le 0 || "${NITRO_PORT}" -gt 4294967295 ]]; then
  echo "Nitro enclave port must be a u32 integer > 0" >&2
  exit 2
fi

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
if [[ -n "${SOLANA_FUNDER_KEYPAIR}" && ! -f "${SOLANA_FUNDER_KEYPAIR}" ]]; then
  echo "solana funder keypair not found: ${SOLANA_FUNDER_KEYPAIR}" >&2
  exit 2
fi

BASE_INFO="$(
  python3 - "${DEPLOYMENTS_FILE}" "${BASE_DEPLOYMENT}" <<'PY'
import json,sys
path=sys.argv[1]
name=sys.argv[2]
with open(path,"r",encoding="utf-8") as f:
  d=json.load(f)
for it in (d.get("deployments") or []):
  if it.get("name")==name:
    def p(k):
      v=str(it.get(k,"") or "").strip()
      print(f"{k}={v}")
    p("cluster"); p("rpc_url"); p("junocash_chain"); p("junocash_genesis_hash")
    p("checkpoint_registry_program_id")
    p("operator_registry_program_id")
    p("intent_escrow_program_id")
    p("receipt_verifier_program_id")
    p("verifier_router_program_id"); p("verifier_router"); p("verifier_entry"); p("verifier_program_id")
    p("address_lookup_table")
    sys.exit(0)
raise SystemExit("deployment not found")
PY
)"

get_field() { printf '%s\n' "${BASE_INFO}" | sed -nE "s/^$1=(.*)$/\\1/p" | head -n 1; }

BASE_CLUSTER="$(get_field cluster)"
BASE_RPC_URL="$(get_field rpc_url)"
JUNOCASH_CHAIN="$(get_field junocash_chain)"
JUNOCASH_GENESIS_EXPECTED="$(get_field junocash_genesis_hash)"
CRP_PROGRAM_ID="$(get_field checkpoint_registry_program_id)"
ORP_PROGRAM_ID="$(get_field operator_registry_program_id)"
IEP_PROGRAM_ID="$(get_field intent_escrow_program_id)"
RECEIPT_VERIFIER_PROGRAM_ID="$(get_field receipt_verifier_program_id)"
VERIFIER_ROUTER_PROGRAM_ID="$(get_field verifier_router_program_id)"
VERIFIER_ROUTER_PDA="$(get_field verifier_router)"
VERIFIER_ENTRY_PDA="$(get_field verifier_entry)"
VERIFIER_PROGRAM_ID="$(get_field verifier_program_id)"
ADDRESS_LOOKUP_TABLE="$(get_field address_lookup_table)"

if [[ "${BASE_CLUSTER}" != "devnet" ]]; then
  echo "base deployment must be devnet (got cluster=${BASE_CLUSTER})" >&2
  exit 2
fi
if [[ "${JUNOCASH_CHAIN}" != "testnet" ]]; then
  echo "base deployment must target junocash_chain=testnet (got ${JUNOCASH_CHAIN})" >&2
  exit 2
fi
if [[ -z "${BASE_RPC_URL}" ]]; then
  echo "base deployment missing rpc_url" >&2
  exit 1
fi
if [[ -z "${CRP_PROGRAM_ID}" || -z "${ORP_PROGRAM_ID}" || -z "${IEP_PROGRAM_ID}" || -z "${RECEIPT_VERIFIER_PROGRAM_ID}" ]]; then
  echo "base deployment missing required program ids" >&2
  printf '%s\n' "${BASE_INFO}" >&2
  exit 1
fi
if [[ -z "${VERIFIER_ROUTER_PROGRAM_ID}" || -z "${VERIFIER_ROUTER_PDA}" || -z "${VERIFIER_ENTRY_PDA}" || -z "${VERIFIER_PROGRAM_ID}" ]]; then
  echo "base deployment missing verifier router accounts/program" >&2
  printf '%s\n' "${BASE_INFO}" >&2
  exit 1
fi

SOLANA_RPC_URL="${SOLANA_RPC_URL:-${RPC_URL_OVERRIDE:-${BASE_RPC_URL}}}"
export SOLANA_RPC_URL

ts="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -n "${WORKDIR_OVERRIDE}" ]]; then
  WORKDIR="${WORKDIR_OVERRIDE}"
else
  WORKDIR="${ROOT}/tmp/e2e/devnet-testnet/${BASE_DEPLOYMENT}/${ts}"
fi
mkdir -p "${WORKDIR}"

SOLVERNET1_PID=""
SOLVERNET2_PID=""

cleanup() {
  if [[ -n "${SOLVERNET1_PID}" ]]; then kill "${SOLVERNET1_PID}" >/dev/null 2>&1 || true; fi
  if [[ -n "${SOLVERNET2_PID}" ]]; then kill "${SOLVERNET2_PID}" >/dev/null 2>&1 || true; fi
  scripts/junocash/testnet/down.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "workdir: ${WORKDIR}" >&2
echo "base_deployment: ${BASE_DEPLOYMENT}" >&2
redact_url() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

raw = sys.argv[1]
try:
  p = urlsplit(raw)
except Exception:
  print(raw)
  raise SystemExit(0)

qs = parse_qsl(p.query, keep_blank_values=True)
redacted = []
for k, v in qs:
  lk = (k or "").lower()
  if lk in ("api-key", "api_key", "apikey", "token") or ("api" in lk and "key" in lk):
    redacted.append((k, "[redacted]" if v else ""))
  else:
    redacted.append((k, v))

query = urlencode(redacted)
print(urlunsplit((p.scheme, p.netloc, p.path, query, p.fragment)))
PY
}
echo "solana_rpc_url: $(redact_url "${SOLANA_RPC_URL}")" >&2
echo "junocash_chain: ${JUNOCASH_CHAIN}" >&2

echo "checking Solana RPC health..." >&2
for _ in $(seq 1 5); do
  if curl -fsS -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
    "${SOLANA_RPC_URL}" >/dev/null; then
    break
  fi
  sleep 2
done
if ! curl -fsS -X POST -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
  "${SOLANA_RPC_URL}" >/dev/null; then
  echo "Solana RPC health check failed; set SOLANA_RPC_URL/--rpc-url to a working endpoint and retry" >&2
  exit 1
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

lamports_to_sol() {
  local lamports="$1"
  python3 - "$lamports" <<'PY'
import sys
lamports=int(sys.argv[1])
whole=lamports//1_000_000_000
frac=lamports%1_000_000_000
if frac==0:
  print(str(whole))
else:
  print(f"{whole}.{frac:09d}".rstrip("0"))
PY
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

wait_for_account_owner() {
  local pubkey="$1"
  local expected_owner="$2"
  local attempts="${3:-60}"
  local owner=""

  for _ in $(seq 1 "${attempts}"); do
    owner="$(
      solana -u "${SOLANA_RPC_URL}" account "${pubkey}" --output json-compact 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("owner",""))' 2>/dev/null \
        || true
    )"
    if [[ -n "${owner}" && "${owner}" == "${expected_owner}" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "account owner mismatch after waiting: pubkey=${pubkey} expected=${expected_owner} got=${owner}" >&2
  return 1
}

	ensure_min_lamports() {
	  local pubkey="$1"
	  local min_lamports="$2"
	  local label="$3"
	  local kp_for_airdrop="$4"

	  local bal_lamports
	  bal_lamports="$(solana_balance_lamports "${pubkey}")"
  if [[ -z "${bal_lamports}" ]]; then
    echo "${label} balance lookup failed (pubkey=${pubkey}); set SOLANA_RPC_URL to a reliable RPC and retry" >&2
    return 1
  fi
  if [[ ! "${bal_lamports}" =~ ^[0-9]+$ ]]; then
    echo "${label} balance lookup returned non-numeric output: ${bal_lamports}" >&2
    return 1
  fi

  if [[ "${bal_lamports}" -ge "${min_lamports}" ]]; then
    return 0
  fi

	  local need_lamports="$((min_lamports - bal_lamports))"

	  if [[ -n "${SOLANA_FUNDER_KEYPAIR}" ]]; then
	    local need_sol
	    need_sol="$(lamports_to_sol "${need_lamports}")"
	    echo "${label} balance low (${bal_lamports} lamports); funding ${need_sol} SOL from solana funder..." >&2
	    local raw funder_pubkey
	    if raw="$(solana -u "${SOLANA_RPC_URL}" transfer --allow-unfunded-recipient "${pubkey}" "${need_sol}" --keypair "${SOLANA_FUNDER_KEYPAIR}" 2>&1)"; then
	      wait_for_account "${pubkey}" 120 || true
	      return 0
	    fi
	    funder_pubkey="$(solana-keygen pubkey "${SOLANA_FUNDER_KEYPAIR}" 2>/dev/null || true)"
	    echo "solana funder transfer failed (funder_pubkey=${funder_pubkey}):" >&2
	    printf '%s\n' "${raw}" >&2
	    echo "falling back to devnet airdrop..." >&2
	  fi

	  local need_sol
	  need_sol="$(lamports_to_sol "${need_lamports}")"
	  echo "${label} balance low (${bal_lamports} lamports); requesting devnet airdrop (${need_sol} SOL)..." >&2
  airdrop "${pubkey}" "${need_sol}" "${kp_for_airdrop}"
}

solana_balance_lamports() {
  local pubkey="$1"
  local attempts="${JUNO_E2E_SOLANA_BALANCE_RETRIES:-10}"
  local delay_secs="${JUNO_E2E_SOLANA_BALANCE_RETRY_DELAY_SECS:-1}"
  local raw out

  if ! [[ "${attempts}" =~ ^[0-9]+$ ]] || [[ "${attempts}" -le 0 ]]; then attempts="10"; fi
  if ! [[ "${delay_secs}" =~ ^[0-9]+$ ]] || [[ "${delay_secs}" -le 0 ]]; then delay_secs="1"; fi

  for _ in $(seq 1 "${attempts}"); do
    raw="$(
      curl -fsS -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"${pubkey}\"]}" \
        "${SOLANA_RPC_URL}" 2>/dev/null || true
    )"
    out="$(
      python3 -c 'import json,sys
try:
  j=json.load(sys.stdin)
except Exception:
  raise SystemExit(0)
v=((j.get("result") or {}).get("value"))
if isinstance(v, int):
  print(v)
' <<<"${raw}" 2>/dev/null || true
    )"
    if [[ "${out}" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "${out}"
      return 0
    fi
    sleep "${delay_secs}"
  done

  if raw="$(solana -u "${SOLANA_RPC_URL}" balance "${pubkey}" --lamports 2>/dev/null)"; then
    python3 -c 'import re,sys
raw=sys.stdin.read()
m=re.search(r"(\\d+)", raw)
print(m.group(1) if m else "")
' <<<"${raw}" 2>/dev/null || true
  fi
  return 0
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

rand_hex32() { python3 -c 'import os; print(os.urandom(32).hex())'; }

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

juno_amount_to_zat() {
  python3 - "$1" <<'PY'
from decimal import Decimal, InvalidOperation
import sys
s=sys.argv[1].strip()
try:
  d=Decimal(s)
except InvalidOperation:
  raise SystemExit(1)
if d < 0:
  raise SystemExit(1)
zat=int((d * Decimal(100000000)).to_integral_value(rounding="ROUND_FLOOR"))
print(zat)
PY
}

receiver_tag_for() {
  local deployment_hex="$1"
  local fill_id_hex="$2"
  local receiver_bytes_hex="$3"
  python3 - "${deployment_hex}" "${fill_id_hex}" "${receiver_bytes_hex}" <<'PY'
import hashlib,sys
dep=bytes.fromhex(sys.argv[1].strip().removeprefix("0x"))
fill=bytes.fromhex(sys.argv[2].strip().removeprefix("0x"))
recv=bytes.fromhex(sys.argv[3].strip().removeprefix("0x"))
if len(dep)!=32 or len(fill)!=32 or len(recv)!=43:
  raise SystemExit("invalid input lengths")
prefix=b"JUNO_INTENTS\x00iep_receiver_tag\x00"+(1).to_bytes(2,"little")
print(hashlib.sha256(prefix+dep+fill+recv).hexdigest())
PY
}

orchard_receiver_bytes_hex() {
  local ua="$1"
  cargo run --quiet --manifest-path "${ROOT}/risc0/receipt/host/Cargo.toml" --bin orchard_receiver_bytes_v1 -- \
    --unified-address "${ua}"
}

rfq_best() {
  # Prints: solver_pubkey_base58 <space> amount_zat_u64 <space> receiver_tag_hex32
  python3 -c 'import json,sys
items=json.load(sys.stdin)
if not isinstance(items, list) or not items:
  raise SystemExit("no quotes")
q=((items[0] or {}).get("signed") or {}).get("quote") or {}
solver=(q.get("solver_pubkey") or "").strip()
amt=q.get("junocash_amount_required")
tag=(q.get("receiver_tag") or "").strip()
if not solver or amt is None or not tag:
  raise SystemExit("invalid quote")
print(solver, amt, tag)
'
}

echo "building Go CLIs..." >&2
GO_INTENTS="${WORKDIR}/juno-intents"
GO_CRP="${WORKDIR}/crp-operator"
GO_CRP_MONITOR="${WORKDIR}/crp-monitor"
GO_SOLVERNET="${WORKDIR}/solvernet"
GO_NITRO="${WORKDIR}/nitro-operator"
(cd "${ROOT}" && go build -o "${GO_INTENTS}" ./cmd/juno-intents)
(cd "${ROOT}" && go build -o "${GO_CRP}" ./cmd/crp-operator)
(cd "${ROOT}" && go build -o "${GO_CRP_MONITOR}" ./cmd/crp-monitor)
(cd "${ROOT}" && go build -o "${GO_SOLVERNET}" ./cmd/solvernet)
(cd "${ROOT}" && go build -o "${GO_NITRO}" ./cmd/nitro-operator)

echo "selecting Solana keypairs..." >&2
SOLVER_KEYPAIR="${WORKDIR}/solver.json"
SOLVER2_KEYPAIR="${WORKDIR}/solver2.json"
CREATOR_KEYPAIR="${WORKDIR}/creator.json"
if [[ -n "${SOLVER_KEYPAIR_OVERRIDE}" ]]; then
  SOLVER_KEYPAIR="${SOLVER_KEYPAIR_OVERRIDE}"
elif [[ ! -s "${SOLVER_KEYPAIR}" ]]; then
  solana-keygen new --no-bip39-passphrase --silent --force -o "${SOLVER_KEYPAIR}"
fi
if [[ -n "${SOLVER2_KEYPAIR_OVERRIDE}" ]]; then
  SOLVER2_KEYPAIR="${SOLVER2_KEYPAIR_OVERRIDE}"
elif [[ ! -s "${SOLVER2_KEYPAIR}" ]]; then
  solana-keygen new --no-bip39-passphrase --silent --force -o "${SOLVER2_KEYPAIR}"
fi
if [[ -n "${CREATOR_KEYPAIR_OVERRIDE}" ]]; then
  CREATOR_KEYPAIR="${CREATOR_KEYPAIR_OVERRIDE}"
elif [[ ! -s "${CREATOR_KEYPAIR}" ]]; then
  solana-keygen new --no-bip39-passphrase --silent --force -o "${CREATOR_KEYPAIR}"
fi
SOLVER_PUBKEY="$(solana-keygen pubkey "${SOLVER_KEYPAIR}")"
SOLVER2_PUBKEY="$(solana-keygen pubkey "${SOLVER2_KEYPAIR}")"
CREATOR_PUBKEY="$(solana-keygen pubkey "${CREATOR_KEYPAIR}")"
echo "solver_pubkey=${SOLVER_PUBKEY}" >&2
echo "solver2_pubkey=${SOLVER2_PUBKEY}" >&2
echo "creator_pubkey=${CREATOR_PUBKEY}" >&2

	if [[ -n "${SOLANA_FUNDER_KEYPAIR}" ]]; then
	  FUNDER_PUBKEY="$(solana-keygen pubkey "${SOLANA_FUNDER_KEYPAIR}")"
	  echo "solana_funder_pubkey=${FUNDER_PUBKEY}" >&2

	  min_solver_lamports="${JUNO_E2E_MIN_SOLVER_LAMPORTS:-250000000}"
	  min_creator_lamports="${JUNO_E2E_MIN_CREATOR_LAMPORTS:-200000000}"
	  min_solver2_lamports="${JUNO_E2E_MIN_SOLVER2_LAMPORTS:-100000000}"
	  funder_buffer_lamports="${JUNO_E2E_SOLANA_FUNDER_BUFFER_LAMPORTS:-50000000}"

	  if [[ ! "${min_solver_lamports}" =~ ^[0-9]+$ ]]; then min_solver_lamports="250000000"; fi
	  if [[ ! "${min_creator_lamports}" =~ ^[0-9]+$ ]]; then min_creator_lamports="200000000"; fi
	  if [[ ! "${min_solver2_lamports}" =~ ^[0-9]+$ ]]; then min_solver2_lamports="100000000"; fi
	  if [[ ! "${funder_buffer_lamports}" =~ ^[0-9]+$ ]]; then funder_buffer_lamports="50000000"; fi

	  solver_balance_now="$(solana_balance_lamports "${SOLVER_PUBKEY}")"
	  creator_balance_now="$(solana_balance_lamports "${CREATOR_PUBKEY}")"
	  solver2_balance_now="$(solana_balance_lamports "${SOLVER2_PUBKEY}")"
	  if [[ -z "${solver_balance_now}" || ! "${solver_balance_now}" =~ ^[0-9]+$ ]]; then
	    echo "solver balance lookup failed; set SOLANA_RPC_URL to a reliable RPC and retry" >&2
	    exit 1
	  fi
	  if [[ -z "${creator_balance_now}" || ! "${creator_balance_now}" =~ ^[0-9]+$ ]]; then
	    echo "creator balance lookup failed; set SOLANA_RPC_URL to a reliable RPC and retry" >&2
	    exit 1
	  fi
	  if [[ -z "${solver2_balance_now}" || ! "${solver2_balance_now}" =~ ^[0-9]+$ ]]; then
	    echo "solver2 balance lookup failed; set SOLANA_RPC_URL to a reliable RPC and retry" >&2
	    exit 1
	  fi

	  need_solver_lamports="0"
	  need_creator_lamports="0"
	  need_solver2_lamports="0"
	  if [[ "${solver_balance_now}" -lt "${min_solver_lamports}" ]]; then
	    need_solver_lamports="$((min_solver_lamports - solver_balance_now))"
	  fi
	  if [[ "${creator_balance_now}" -lt "${min_creator_lamports}" ]]; then
	    need_creator_lamports="$((min_creator_lamports - creator_balance_now))"
	  fi
	  if [[ "${solver2_balance_now}" -lt "${min_solver2_lamports}" ]]; then
	    need_solver2_lamports="$((min_solver2_lamports - solver2_balance_now))"
	  fi

	  funder_min_lamports="$((need_solver_lamports + need_creator_lamports + need_solver2_lamports))"
	  if [[ "${funder_min_lamports}" -gt 0 ]]; then
	    funder_min_lamports="$((funder_min_lamports + funder_buffer_lamports))"
	  fi
	  funder_min_sol="$(lamports_to_sol "${funder_min_lamports}")"

	  if [[ "${funder_min_lamports}" -le 0 ]]; then
	    echo "solana funder not needed (all accounts funded)" >&2
	  else
	    funder_wait_timeout_secs="${JUNO_E2E_SOLANA_FUNDER_WAIT_TIMEOUT_SECS:-3600}"
	    if ! [[ "${funder_wait_timeout_secs}" =~ ^[0-9]+$ ]] || [[ "${funder_wait_timeout_secs}" -le 0 ]]; then
	      funder_wait_timeout_secs="3600"
	    fi

	    echo "waiting for solana funder balance >= ${funder_min_sol} SOL (lamports=${funder_min_lamports})..." >&2
	    funder_poll_secs=10
	    funder_elapsed=0
	    funder_progress_secs=60
	    while [[ "${funder_elapsed}" -lt "${funder_wait_timeout_secs}" ]]; do
	      funder_balance_now="$(solana_balance_lamports "${FUNDER_PUBKEY}")"
	      if [[ -z "${funder_balance_now}" || ! "${funder_balance_now}" =~ ^[0-9]+$ ]]; then
	        echo "solana funder balance lookup failed; set SOLANA_RPC_URL to a reliable RPC and retry" >&2
	        exit 1
	      fi
	      if [[ "${funder_balance_now}" =~ ^[0-9]+$ ]] && [[ "${funder_balance_now}" -ge "${funder_min_lamports}" ]]; then
	        break
	      fi
	      if (( funder_elapsed % funder_progress_secs == 0 )); then
	        fb_str="0.0"
	        if [[ "${funder_balance_now}" =~ ^[0-9]+$ ]]; then fb_str="$(lamports_to_sol "${funder_balance_now}")"; fi
	        echo "waiting for solana funder funds... balance=${fb_str} required=${funder_min_sol} elapsed=${funder_elapsed}s" >&2
	      fi
	      sleep "${funder_poll_secs}"
	      funder_elapsed="$((funder_elapsed + funder_poll_secs))"
	    done
	    if [[ ! "${funder_balance_now}" =~ ^[0-9]+$ ]] || [[ "${funder_balance_now}" -lt "${funder_min_lamports}" ]]; then
	      echo "solana funder not funded enough: pubkey=${FUNDER_PUBKEY} required_sol=${funder_min_sol}" >&2
	      exit 1
	    fi
	  fi
	fi

	echo "funding Solana keypairs..." >&2
	ensure_min_lamports "${SOLVER_PUBKEY}" "${JUNO_E2E_MIN_SOLVER_LAMPORTS:-250000000}" "solver" "${SOLVER_KEYPAIR}"
	ensure_min_lamports "${CREATOR_PUBKEY}" "${JUNO_E2E_MIN_CREATOR_LAMPORTS:-200000000}" "creator" "${CREATOR_KEYPAIR}"

	min_solver2_lamports="${JUNO_E2E_MIN_SOLVER2_LAMPORTS:-100000000}"
	solver2_balance_now="$(solana_balance_lamports "${SOLVER2_PUBKEY}")"
if [[ ! "${solver2_balance_now}" =~ ^[0-9]+$ ]]; then solver2_balance_now="0"; fi
if [[ "${solver2_balance_now}" -lt "${min_solver2_lamports}" ]]; then
  if [[ -n "${SOLANA_FUNDER_KEYPAIR}" ]]; then
    ensure_min_lamports "${SOLVER2_PUBKEY}" "${min_solver2_lamports}" "solver2" "${SOLVER2_KEYPAIR}"
  elif [[ -z "${SOLVER2_KEYPAIR_OVERRIDE}" ]]; then
    solver2_need_lamports="$((min_solver2_lamports - solver2_balance_now))"
    solver2_need_sol="$(lamports_to_sol "${solver2_need_lamports}")"
    echo "solver2 balance low (${solver2_balance_now} lamports); funding ${solver2_need_sol} SOL from solver..." >&2
    solana -u "${SOLANA_RPC_URL}" transfer --allow-unfunded-recipient "${SOLVER2_PUBKEY}" "${solver2_need_sol}" --keypair "${SOLVER_KEYPAIR}" >/dev/null
  else
    echo "solver2 balance low; provide JUNO_E2E_SOLVER2_KEYPAIR with funds" >&2
    exit 1
  fi
fi

echo "creating wJUNO SPL mint + token accounts..." >&2
if ! MINT_OUT="$(retry 5 3 spl-token -u "${SOLANA_RPC_URL}" create-token --decimals 0 --owner "${SOLVER_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact)"; then
  echo "spl-token create-token failed" >&2
  exit 1
fi
MINT="$(parse_spl_address <<<"${MINT_OUT}")"
MINT_SIG="$(parse_spl_signature <<<"${MINT_OUT}" || true)"
if [[ -n "${MINT_SIG}" ]]; then solana -u "${SOLANA_RPC_URL}" confirm "${MINT_SIG}" >/dev/null 2>&1 || true; fi

SOLVER_TA="$(ata_for "${SOLVER_PUBKEY}" "${MINT}")"
SOLVER2_TA="$(ata_for "${SOLVER2_PUBKEY}" "${MINT}")"
CREATOR_TA="$(ata_for "${CREATOR_PUBKEY}" "${MINT}")"
FEE_TA="$(ata_for "${FEE_COLLECTOR_PUBKEY}" "${MINT}")"

spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${SOLVER_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null
spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${SOLVER2_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null
spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${CREATOR_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null
spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${FEE_COLLECTOR_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null

for target in "${SOLVER_TA}" "${SOLVER2_TA}" "${CREATOR_TA}"; do
  spl-token -u "${SOLANA_RPC_URL}" mint "${MINT}" 1000000 "${target}" --mint-authority "${SOLVER_KEYPAIR}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null
done

EXPIRY_SLOT_DELTA="${JUNO_E2E_EXPIRY_SLOT_DELTA:-20000}"
if ! [[ "${EXPIRY_SLOT_DELTA}" =~ ^[0-9]+$ ]] || [[ "${EXPIRY_SLOT_DELTA}" -le 0 ]]; then
  echo "invalid JUNO_E2E_EXPIRY_SLOT_DELTA: ${EXPIRY_SLOT_DELTA}" >&2
  exit 2
fi

solana_current_slot() {
  local latest_blockhash_json
  latest_blockhash_json="$(retry 10 3 curl -fsS -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash"}' "${SOLANA_RPC_URL}")"
  printf '%s' "${latest_blockhash_json}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["context"]["slot"])' | tr -d '\r\n '
}

solana_expiry_slot() {
  local slot
  slot="$(solana_current_slot)"
  if ! [[ "${slot}" =~ ^[0-9]+$ ]]; then
    echo "failed to read solana slot from rpc" >&2
    exit 1
  fi
  echo "$((slot + EXPIRY_SLOT_DELTA))"
}

echo "preparing JunoCash testnet data dir..." >&2
export JUNO_TESTNET_DATA_DIR_A="${WORKDIR}/junocash-testnet-a"
mkdir -p "${JUNO_TESTNET_DATA_DIR_A}/testnet3"

if [[ -n "${JUNOCASH_TESTNET_WALLET_DAT_GZ_B64}" ]]; then
  echo "seeding junocash testnet wallet.dat from JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64..." >&2
  python3 - "${JUNO_TESTNET_DATA_DIR_A}/testnet3/wallet.dat" <<'PY'
import base64,gzip,os,sys
out=sys.argv[1]
b64=os.environ.get("JUNO_E2E_JUNOCASH_TESTNET_WALLET_DAT_GZ_B64","")
payload=base64.b64decode("".join(b64.split()))
raw=gzip.decompress(payload)
with open(out,"wb") as f:
  f.write(raw)
PY
  chmod 600 "${JUNO_TESTNET_DATA_DIR_A}/testnet3/wallet.dat" || true
fi

echo "starting JunoCash testnet docker harness..." >&2
export JUNO_TESTNET_MODE="${JUNOCASH_TESTNET_MODE}"
scripts/junocash/testnet/up.sh >/dev/null

jcli() { scripts/junocash/testnet/cli.sh "$@"; }

z_sendmany_opid() {
  local from="$1"
  local recipients_json="$2"
  local minconf="${3:-1}"

  local raw
  if ! raw="$(jcli z_sendmany "${from}" "${recipients_json}" "${minconf}" 2>&1)"; then
    echo "z_sendmany failed:" >&2
    printf '%s\n' "${raw}" >&2
    return 1
  fi

  local opid
  opid="$(
    python3 - "${raw}" 2>/dev/null <<'PY' || true
import re,sys
raw=sys.argv[1].strip()
if not raw:
  raise SystemExit(1)
raw=raw.strip().strip('"')
m=re.search(r"(opid-[A-Za-z0-9-]+)", raw)
if m:
  print(m.group(1))
  raise SystemExit(0)
if raw.startswith("opid-"):
  print(raw)
  raise SystemExit(0)
raise SystemExit(1)
PY
  )"
  if [[ -z "${opid}" ]]; then
    echo "failed to parse opid from z_sendmany output:" >&2
    printf '%s\n' "${raw}" >&2
    return 1
  fi
  printf '%s\n' "${opid}"
}

wait_for_wallet_scan_complete() {
  local wait_secs="${1:-3600}"
  local elapsed=0
  while [[ "${elapsed}" -lt "${wait_secs}" ]]; do
    info="$(jcli getwalletinfo 2>/dev/null || true)"
    if [[ -n "${info}" ]]; then
      done="$(
        python3 -c 'import json,sys
try: j=json.load(sys.stdin)
except Exception: print("0"); raise SystemExit(0)
sc=j.get("scanning", None)
if sc is False or sc is None:
  print("1"); raise SystemExit(0)
print("0")
' <<<"${info}"
      )"
      if [[ "${done}" == "1" ]]; then
        return 0
      fi
    fi
    sleep 1
    elapsed="$((elapsed + 1))"
  done
  echo "wallet scan did not complete (timeout=${wait_secs}s)" >&2
  return 1
}

echo "mining one block (sync + baseline)..." >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null

wait_for_wallet_scan_complete "${JUNO_E2E_WALLET_SCAN_TIMEOUT_SECS:-3600}"

echo "verifying junocash genesis hash..." >&2
genesis="$(jcli getblockhash 0 | tr -d '\" \r\n')"
genesis_norm="$(printf '%s' "${genesis}" | tr '[:upper:]' '[:lower:]' | tr -d '\" \t\r\n' | sed -E 's/^0x//')"
expected_genesis_norm="$(printf '%s' "${JUNOCASH_GENESIS_EXPECTED}" | tr '[:upper:]' '[:lower:]' | tr -d '\" \t\r\n' | sed -E 's/^0x//')"
if [[ "${genesis_norm}" != "${expected_genesis_norm}" ]]; then
  echo "junocash genesis mismatch: got ${genesis_norm} want ${expected_genesis_norm}" >&2
  exit 1
fi

echo "creating JunoCash accounts + orchard UAs..." >&2
if read -r USER_ACCOUNT USER_UA <<<"$(
  jcli z_listaccounts | python3 -c 'import json,sys
items=json.load(sys.stdin)
if not isinstance(items, list) or not items:
  raise SystemExit(1)
it=items[0] or {}
acct=it.get("account")
addrs=it.get("addresses") or []
ua=((addrs[0] or {}).get("ua") or "").strip() if addrs else ""
if acct is None or ua == "":
  raise SystemExit(1)
print(int(acct), ua)
'
)"; then
  :
else
  USER_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
  USER_UA="$(jcli z_getaddressforaccount "${USER_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
fi
SOLVER1_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
SOLVER2_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
SOLVER1_UA="$(jcli z_getaddressforaccount "${SOLVER1_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
SOLVER2_UA="$(jcli z_getaddressforaccount "${SOLVER2_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
echo "user_ua=${USER_UA}" >&2
echo "solver1_ua=${SOLVER1_UA}" >&2
echo "solver2_ua=${SOLVER2_UA}" >&2

echo "checking JunoCash funding (orchard-only)..." >&2
prefund_amount_ok="$(
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
if [[ -z "${prefund_amount_ok}" ]]; then
  echo "invalid JUNO_E2E_JUNOCASH_TESTNET_PREFUND_AMOUNT: ${JUNOCASH_TESTNET_PREFUND_AMOUNT}" >&2
  exit 2
fi

prefund_min_zat="$(juno_amount_to_zat "${prefund_amount_ok}")"

	balance_zat() {
	  local acct="$1"
	  local minconf="$2"
	  local raw out

	  if ! [[ "${minconf}" =~ ^[0-9]+$ ]]; then
	    minconf="1"
	  fi

	  raw="$(jcli z_getbalanceforaccount "${acct}" "${minconf}" 2>/dev/null || true)"
	  out="$(
	    python3 -c 'import json,sys
try:
  j=json.load(sys.stdin)
except Exception:
  raise SystemExit(1)
p=(j.get("pools") or {})
o=(p.get("orchard") or {})
v=o.get("valueZat", 0)
if isinstance(v, bool):
  raise SystemExit(1)
if isinstance(v, int):
  print(v); raise SystemExit(0)
try:
  print(int(v))
except Exception:
  raise SystemExit(1)
' <<<"${raw}" 2>/dev/null || true
  )"
  if [[ ! "${out}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  printf '%s\n' "${out}"
	}

	# minconf=0 includes unconfirmed orchard notes. We accept this for prefunding
	# so the E2E can proceed and later mine enough confirmations for spending.
	current_any_zat="$(balance_zat "${USER_ACCOUNT}" 0 2>/dev/null || true)"
	if [[ ! "${current_any_zat}" =~ ^[0-9]+$ ]]; then current_any_zat="0"; fi
	if [[ "${current_any_zat}" -lt "${prefund_min_zat}" ]]; then
	  echo "wallet needs funding: send >=${prefund_amount_ok} JunoCash testnet to:" >&2
	  echo "fund_user_ua=${USER_UA}" >&2
  if ! [[ "${JUNOCASH_TESTNET_FUND_TIMEOUT_SECS}" =~ ^[0-9]+$ ]] || [[ "${JUNOCASH_TESTNET_FUND_TIMEOUT_SECS}" -le 0 ]]; then
    JUNOCASH_TESTNET_FUND_TIMEOUT_SECS="3600"
  fi
  poll_secs=5
	  elapsed=0
	  progress_secs=30
	  while [[ "${elapsed}" -lt "${JUNOCASH_TESTNET_FUND_TIMEOUT_SECS}" ]]; do
	    wait_for_wallet_scan_complete 60 || true
	    current_any_zat="$(balance_zat "${USER_ACCOUNT}" 0 2>/dev/null || true)"
	    if [[ "${current_any_zat}" =~ ^[0-9]+$ ]] && [[ "${current_any_zat}" -ge "${prefund_min_zat}" ]]; then
	      break
	    fi
	    if (( elapsed % progress_secs == 0 )); then
      cur_str="0.0"
      if [[ "${current_any_zat}" =~ ^[0-9]+$ ]]; then cur_str="$(zat_to_junocash_amount "${current_any_zat}")"; fi
      echo "waiting for funds... balance=${cur_str} required=${prefund_amount_ok} elapsed=${elapsed}s" >&2
    fi
    sleep "${poll_secs}"
    elapsed="$((elapsed + poll_secs))"
  done
  if [[ ! "${current_any_zat}" =~ ^[0-9]+$ ]] || [[ "${current_any_zat}" -lt "${prefund_min_zat}" ]]; then
    echo "timed out waiting for JunoCash funds (timeout=${JUNOCASH_TESTNET_FUND_TIMEOUT_SECS}s)" >&2
    exit 1
  fi
fi

confirmed_zat="$(balance_zat "${USER_ACCOUNT}" "${JUNOCASH_SEND_MINCONF}" 2>/dev/null || true)"
if [[ ! "${confirmed_zat}" =~ ^[0-9]+$ ]]; then confirmed_zat="0"; fi
if [[ "${confirmed_zat}" -lt "${prefund_min_zat}" ]]; then
  echo "mining ${JUNOCASH_SEND_MINCONF} blocks to reach minconf=${JUNOCASH_SEND_MINCONF}..." >&2
  scripts/junocash/testnet/mine.sh "${JUNOCASH_SEND_MINCONF}" >/dev/null
  wait_for_wallet_scan_complete "${JUNO_E2E_WALLET_SCAN_TIMEOUT_SECS:-3600}"
fi

USER_ORCHARD_RECEIVER_HEX="$(orchard_receiver_bytes_hex "${USER_UA}")"
SOLVER1_ORCHARD_RECEIVER_HEX="$(orchard_receiver_bytes_hex "${SOLVER1_UA}")"
SOLVER2_ORCHARD_RECEIVER_HEX="$(orchard_receiver_bytes_hex "${SOLVER2_UA}")"

DEPLOYMENT_ID_HEX="$(rand_hex32)"
echo "deployment_id=${DEPLOYMENT_ID_HEX}" >&2

echo "attesting + registering Nitro operators in ORP..." >&2
JUNOCASH_CHAIN_ID="2"

OP_BUNDLE_1=""
OP_BUNDLE_2=""
OP_PUBKEY_1=""
OP_PUBKEY_2=""
OP_MEAS_1=""
OP_MEAS_2=""

for idx in 1 2; do
  cid_var="NITRO_CID${idx}"
  cid="${!cid_var}"

  pub_out="$("${GO_NITRO}" pubkey --enclave-cid "${cid}" --enclave-port "${NITRO_PORT}")"
  op_pub_b58="$(printf '%s\n' "${pub_out}" | sed -nE 's/^operator_pubkey_base58=(.+)$/\1/p' | head -n 1)"
  if [[ -z "${op_pub_b58}" ]]; then
    echo "failed to parse operator pubkey from nitro-operator pubkey" >&2
    printf '%s\n' "${pub_out}" >&2
    exit 1
  fi

  bundle_file="${WORKDIR}/op_bundle_${idx}_${DEPLOYMENT_ID_HEX}.hex"
  if [[ -f "${bundle_file}" ]]; then
    bundle_hex="$(tr -d ' \t\r\n' <"${bundle_file}")"
  else
    witness_hex="$("${GO_NITRO}" witness --enclave-cid "${cid}" --enclave-port "${NITRO_PORT}" --deployment-id "${DEPLOYMENT_ID_HEX}" --junocash-chain-id "${JUNOCASH_CHAIN_ID}" --junocash-genesis-hash "${JUNOCASH_GENESIS_EXPECTED}")"
    raw_bundle_hex="$(risc0_prove_bundle risc0/attestation/host/Cargo.toml prove_attestation_bundle_v1 "${witness_hex}")"
    bundle_hex="$(printf '%s\n' "${raw_bundle_hex}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1 || true)"
    if [[ -z "${bundle_hex}" ]]; then
      echo "failed to extract attestation bundle hex" >&2
      exit 1
    fi
    printf '%s\n' "${bundle_hex}" >"${bundle_file}"
  fi

  info="$("${GO_INTENTS}" orp-attestation-info --bundle-hex "${bundle_hex}")"
  meas="$(printf '%s\n' "${info}" | sed -nE 's/^measurement=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
  op_b58_in_bundle="$(printf '%s\n' "${info}" | sed -nE 's/^operator_pubkey=([1-9A-HJ-NP-Za-km-z]+)$/\1/p' | head -n 1)"
  if [[ -z "${meas}" || -z "${op_b58_in_bundle}" ]]; then
    echo "failed to parse attestation info" >&2
    printf '%s\n' "${info}" >&2
    exit 1
  fi
  if [[ "${op_b58_in_bundle}" != "${op_pub_b58}" ]]; then
    echo "operator pubkey mismatch between nitro enclave and bundle" >&2
    echo "nitro=${op_pub_b58}" >&2
    echo "bundle=${op_b58_in_bundle}" >&2
    exit 1
  fi

  if [[ "${idx}" == "1" ]]; then
    OP_PUBKEY_1="${op_pub_b58}"
    OP_BUNDLE_1="${bundle_hex}"
    OP_MEAS_1="${meas}"
  else
    OP_PUBKEY_2="${op_pub_b58}"
    OP_BUNDLE_2="${bundle_hex}"
    OP_MEAS_2="${meas}"
  fi
done

echo "init ORP/CRP/IEP configs..." >&2
ORP_CONFIG="$("${GO_INTENTS}" pda --program-id "${ORP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --print config)"
retry 5 3 "${GO_INTENTS}" init-orp \
  --orp-program-id "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --admin "${SOLVER_PUBKEY}" \
  --junocash-chain-id "${JUNOCASH_CHAIN_ID}" \
  --junocash-genesis-hash "${JUNOCASH_GENESIS_EXPECTED}" \
  --verifier-router-program "${VERIFIER_ROUTER_PROGRAM_ID}" \
  --verifier-program-id "${VERIFIER_PROGRAM_ID}" \
  --allowed-measurement "${OP_MEAS_1}" \
  --allowed-measurement "${OP_MEAS_2}" \
  --payer-keypair "${SOLVER_KEYPAIR}"
wait_for_account "${ORP_CONFIG}" 60
wait_for_account_owner "${ORP_CONFIG}" "${ORP_PROGRAM_ID}" 60

retry 5 3 "${GO_INTENTS}" orp-register-operator \
  --orp-program-id "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --bundle-hex "${OP_BUNDLE_1}" \
  --payer-keypair "${SOLVER_KEYPAIR}"

retry 5 3 "${GO_INTENTS}" orp-register-operator \
  --orp-program-id "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --bundle-hex "${OP_BUNDLE_2}" \
  --payer-keypair "${SOLVER_KEYPAIR}"

retry 5 3 "${GO_INTENTS}" init-crp \
  --crp-program-id "${CRP_PROGRAM_ID}" \
  --operator-registry-program "${ORP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --admin "${FEE_COLLECTOR_PUBKEY}" \
  --threshold 2 \
  --conflict-threshold 2 \
  --finalization-delay-slots 0 \
  --operator "${OP_PUBKEY_1}" \
  --operator "${OP_PUBKEY_2}" \
  --payer-keypair "${SOLVER_KEYPAIR}"
CRP_CONFIG="$("${GO_INTENTS}" pda --program-id "${CRP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --print config)"
wait_for_account "${CRP_CONFIG}" 60
wait_for_account_owner "${CRP_CONFIG}" "${CRP_PROGRAM_ID}" 60

retry 5 3 "${GO_INTENTS}" init-iep \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --mint "${MINT}" \
  --checkpoint-registry-program "${CRP_PROGRAM_ID}" \
  --receipt-verifier-program "${RECEIPT_VERIFIER_PROGRAM_ID}" \
  --verifier-router-program "${VERIFIER_ROUTER_PROGRAM_ID}" \
  --verifier-router "${VERIFIER_ROUTER_PDA}" \
  --verifier-entry "${VERIFIER_ENTRY_PDA}" \
  --verifier-program "${VERIFIER_PROGRAM_ID}" \
  --payer-keypair "${SOLVER_KEYPAIR}"
IEP_CONFIG="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --print config)"
wait_for_account "${IEP_CONFIG}" 60
wait_for_account_owner "${IEP_CONFIG}" "${IEP_PROGRAM_ID}" 60

echo "starting solvernet solvers (auto-fill)..." >&2
SOLVERNET1_LISTEN="${JUNO_E2E_SOLVERNET1_LISTEN:-127.0.0.1:8081}"
SOLVERNET2_LISTEN="${JUNO_E2E_SOLVERNET2_LISTEN:-127.0.0.1:8082}"
SOLVERNET_POLL_INTERVAL="${JUNO_E2E_SOLVERNET_POLL_INTERVAL:-10s}"
SOLVERNET1_QUOTE_URL="http://${SOLVERNET1_LISTEN}/v1/quote"
SOLVERNET2_QUOTE_URL="http://${SOLVERNET2_LISTEN}/v1/quote"
SOLVERNET1_ANN_URL="http://${SOLVERNET1_LISTEN}/v1/announcement"
SOLVERNET2_ANN_URL="http://${SOLVERNET2_LISTEN}/v1/announcement"

SOLVERNET1_PRICE="${JUNO_E2E_SOLVERNET1_PRICE_ZAT_PER_UNIT:-100000}"
SOLVERNET1_SPREAD="${JUNO_E2E_SOLVERNET1_SPREAD_BPS:-0}"
SOLVERNET2_PRICE="${JUNO_E2E_SOLVERNET2_PRICE_ZAT_PER_UNIT:-110000}"
SOLVERNET2_SPREAD="${JUNO_E2E_SOLVERNET2_SPREAD_BPS:-500}"

"${GO_SOLVERNET}" run \
  --listen "${SOLVERNET1_LISTEN}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --quote-url "${SOLVERNET1_QUOTE_URL}" \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --solver-token-account "${SOLVER_TA}" \
  --mint "${MINT}" \
  --price-zat-per-token-unit "${SOLVERNET1_PRICE}" \
  --spread-bps "${SOLVERNET1_SPREAD}" \
  --orchard-receiver-bytes-hex "${SOLVER1_ORCHARD_RECEIVER_HEX}" \
  --poll-interval "${SOLVERNET_POLL_INTERVAL}" \
  --keypair "${SOLVER_KEYPAIR}" \
  >"${WORKDIR}/solvernet1.log" 2>&1 &
SOLVERNET1_PID="$!"

"${GO_SOLVERNET}" run \
  --listen "${SOLVERNET2_LISTEN}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --quote-url "${SOLVERNET2_QUOTE_URL}" \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --solver-token-account "${SOLVER2_TA}" \
  --mint "${MINT}" \
  --price-zat-per-token-unit "${SOLVERNET2_PRICE}" \
  --spread-bps "${SOLVERNET2_SPREAD}" \
  --orchard-receiver-bytes-hex "${SOLVER2_ORCHARD_RECEIVER_HEX}" \
  --poll-interval "${SOLVERNET_POLL_INTERVAL}" \
  --keypair "${SOLVER2_KEYPAIR}" \
  >"${WORKDIR}/solvernet2.log" 2>&1 &
SOLVERNET2_PID="$!"

for _ in $(seq 1 60); do
  if curl -fsS "${SOLVERNET1_ANN_URL}" >/dev/null 2>&1 && curl -fsS "${SOLVERNET2_ANN_URL}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "${SOLVERNET1_ANN_URL}" >/dev/null
curl -fsS "${SOLVERNET2_ANN_URL}" >/dev/null

select_solver_by_pubkey() {
  local solver_pubkey="$1"
  case "${solver_pubkey}" in
    "${SOLVER_PUBKEY}") echo "${SOLVER_KEYPAIR} ${SOLVER_TA} ${SOLVER1_ACCOUNT} ${SOLVER1_UA} ${SOLVER1_ORCHARD_RECEIVER_HEX}" ;;
    "${SOLVER2_PUBKEY}") echo "${SOLVER2_KEYPAIR} ${SOLVER2_TA} ${SOLVER2_ACCOUNT} ${SOLVER2_UA} ${SOLVER2_ORCHARD_RECEIVER_HEX}" ;;
    *) echo "unknown solver pubkey: ${solver_pubkey}" >&2; return 1 ;;
  esac
}

echo "=== Direction A (JunoCash -> wJUNO) ===" >&2
INTENT_NONCE_A="$(rand_hex32)"
EXPIRY_SLOT_A="$(solana_expiry_slot)"
echo "expiry_slot_a=${EXPIRY_SLOT_A} (delta=${EXPIRY_SLOT_DELTA})" >&2
FILL_ID_A_HEX="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_A}" --print fill-id-hex)"
INTENT_A="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_A}" --print intent)"
FILL_A="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_A}" --print fill)"

rfq_a="$("${GO_SOLVERNET}" rfq \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_A_HEX}" \
  --direction A \
  --mint "${MINT}" \
  --net-amount "${NET_AMOUNT_A}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --intent-expiry-slot "${EXPIRY_SLOT_A}" \
  --announcement-url "${SOLVERNET1_ANN_URL}" \
  --announcement-url "${SOLVERNET2_ANN_URL}")"
printf '%s\n' "${rfq_a}" >"${WORKDIR}/rfq_a.json"
read -r SOLVER_A_PUBKEY AMOUNT_A_ZAT RECEIVER_TAG_A <<<"$(rfq_best <<<"${rfq_a}")"
solver_a_info="$(select_solver_by_pubkey "${SOLVER_A_PUBKEY}")"
read -r SOLVER_A_KEYPAIR SOLVER_A_TA SOLVER_A_ACCOUNT SOLVER_A_UA _SOLVER_A_ORCHARD_RECEIVER_HEX <<<"${solver_a_info}"
PAYMENT_AMOUNT_A_STR="$(zat_to_junocash_amount "${AMOUNT_A_ZAT}")"
echo "solver_a_pubkey=${SOLVER_A_PUBKEY}" >&2
echo "intent_a=${INTENT_A}" >&2
echo "fill_a=${FILL_A}" >&2

retry 20 5 "${GO_INTENTS}" iep-create-intent \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --intent-nonce "${INTENT_NONCE_A}" \
  --direction A \
  --mint "${MINT}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --net-amount "${NET_AMOUNT_A}" \
  --expiry-slot "${EXPIRY_SLOT_A}" \
  --solver "${SOLVER_A_PUBKEY}" \
  --receiver-tag "${RECEIVER_TAG_A}" \
  --junocash-amount "${AMOUNT_A_ZAT}" \
  --creator-keypair "${CREATOR_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

echo "waiting for solver fill (A)..." >&2
wait_for_account "${FILL_A}" 120

echo "sending JunoCash payment user->solver (amount=${PAYMENT_AMOUNT_A_STR})..." >&2
recipients_a="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${SOLVER_A_UA}" "${PAYMENT_AMOUNT_A_STR}")"
opid_a="$(retry 5 3 z_sendmany_opid "${USER_UA}" "${recipients_a}" "${JUNOCASH_SEND_MINCONF}")"
txid_a="$(
  python3 - <<PY
import json,subprocess,sys,time
opid='${opid_a}'
for _ in range(1800):
  out=subprocess.check_output(['scripts/junocash/testnet/cli.sh','z_getoperationresult',f'["{opid}"]']).decode()
  try:
    items=json.loads(out)
  except Exception:
    time.sleep(1); continue
  if not items:
    time.sleep(1); continue
  it=items[0]
  if it.get('status')=='success':
    print((it.get('result') or {}).get('txid',''))
    sys.exit(0)
  if it.get('status')=='failed':
    print(json.dumps(it)); sys.exit(1)
  time.sleep(1)
print('')
sys.exit(1)
PY
)" || { echo "sendmany op failed (A)" >&2; exit 1; }
echo "txid_a=${txid_a}" >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null
PAYMENT_HEIGHT_A="$(jcli getblockcount)"

echo "finding solver note outindex (A)..." >&2
ACTION_A="$(
  jcli z_listunspent 1 9999999 false | python3 -c 'import json,sys
notes=json.load(sys.stdin)
txid=sys.argv[1].strip().lower()
acct=int(sys.argv[2])
for n in notes:
  if str(n.get("pool"))!="orchard":
    continue
  if str(n.get("txid","")).strip().lower()!=txid:
    continue
  if n.get("account")!=acct or not n.get("spendable"):
    continue
  print(n.get("outindex")); sys.exit(0)
sys.exit(1)
' "${txid_a}" "${SOLVER_A_ACCOUNT}"
)" || { echo "failed to find action index (A)" >&2; exit 1; }

echo "generating witness (A)..." >&2
DATA_DIR="${JUNO_TESTNET_DATA_DIR_A}"
WALLET_DAT=""
for p in "${DATA_DIR}/testnet3/wallet.dat" "${DATA_DIR}/wallet.dat" "${DATA_DIR}/testnet3/wallets/wallet.dat" "${DATA_DIR}/wallets/wallet.dat"; do
  if [[ -f "${p}" ]]; then WALLET_DAT="${p}"; break; fi
done
if [[ -z "${WALLET_DAT}" ]]; then echo "wallet.dat not found under ${DATA_DIR}" >&2; exit 1; fi

db_dump_flag=()
if [[ "${JUNO_DB_DUMP:-}" != "" ]]; then
  db_dump_flag=(--db-dump "${JUNO_DB_DUMP}")
elif [[ -x "/opt/homebrew/opt/berkeley-db/bin/db_dump" ]]; then
  db_dump_flag=(--db-dump "/opt/homebrew/opt/berkeley-db/bin/db_dump")
elif command -v db_dump >/dev/null; then
  db_dump_flag=(--db-dump "db_dump")
elif command -v db5.3_dump >/dev/null; then
  db_dump_flag=(--db-dump "db5.3_dump")
fi

wallet_backup_file_a="walletwitnessadat"
rm -f "${DATA_DIR}/${wallet_backup_file_a}" >/dev/null 2>&1 || true
jcli backupwallet "${wallet_backup_file_a}" >/dev/null
WALLET_WITNESS_DAT_A="${DATA_DIR}/${wallet_backup_file_a}"
WITNESS_A="$(cd "${ROOT}" && cargo run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli scripts/junocash/testnet/cli.sh \
  --wallet "${WALLET_WITNESS_DAT_A}" \
  "${db_dump_flag[@]}" \
  --txid "${txid_a}" \
  --action "${ACTION_A}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_A_HEX}")"

INPUTS_A="$(JUNO_RECEIPT_WITNESS_HEX="${WITNESS_A}" "${GO_INTENTS}" receipt-inputs --json=false)"
AMOUNT_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^amount=([0-9]+)$/\1/p' | head -n 1)"
RECEIVER_TAG_A_WITNESS="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^receiver_tag=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
ORCHARD_ROOT_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^orchard_root=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
if [[ "${AMOUNT_A}" != "${AMOUNT_A_ZAT}" || "${RECEIVER_TAG_A_WITNESS}" != "${RECEIVER_TAG_A}" ]]; then
  echo "witness mismatch (A): amount/receiver_tag" >&2
  exit 1
fi

echo "=== Direction B (wJUNO -> JunoCash) ===" >&2
INTENT_NONCE_B="$(rand_hex32)"
EXPIRY_SLOT_B="$(solana_expiry_slot)"
echo "expiry_slot_b=${EXPIRY_SLOT_B} (delta=${EXPIRY_SLOT_DELTA})" >&2
FILL_ID_B_HEX="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_B}" --print fill-id-hex)"
INTENT_B="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_B}" --print intent)"
FILL_B="$("${GO_INTENTS}" pda --program-id "${IEP_PROGRAM_ID}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_B}" --print fill)"
RECEIVER_TAG_B="$(receiver_tag_for "${DEPLOYMENT_ID_HEX}" "${FILL_ID_B_HEX}" "${USER_ORCHARD_RECEIVER_HEX}")"

rfq_b="$("${GO_SOLVERNET}" rfq \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_B_HEX}" \
  --direction B \
  --receiver-tag "${RECEIVER_TAG_B}" \
  --mint "${MINT}" \
  --net-amount "${NET_AMOUNT_B}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --intent-expiry-slot "${EXPIRY_SLOT_B}" \
  --announcement-url "${SOLVERNET1_ANN_URL}" \
  --announcement-url "${SOLVERNET2_ANN_URL}")"
printf '%s\n' "${rfq_b}" >"${WORKDIR}/rfq_b.json"
read -r SOLVER_B_PUBKEY AMOUNT_B_ZAT _TAG_B <<<"$(rfq_best <<<"${rfq_b}")"
solver_b_info="$(select_solver_by_pubkey "${SOLVER_B_PUBKEY}")"
read -r SOLVER_B_KEYPAIR SOLVER_B_TA SOLVER_B_ACCOUNT SOLVER_B_UA _SOLVER_B_ORCHARD_RECEIVER_HEX <<<"${solver_b_info}"
PAYMENT_AMOUNT_B_STR="$(zat_to_junocash_amount "${AMOUNT_B_ZAT}")"
echo "solver_b_pubkey=${SOLVER_B_PUBKEY}" >&2
echo "intent_b=${INTENT_B}" >&2
echo "fill_b=${FILL_B}" >&2

retry 20 5 "${GO_INTENTS}" iep-create-intent \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --intent-nonce "${INTENT_NONCE_B}" \
  --direction B \
  --mint "${MINT}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --net-amount "${NET_AMOUNT_B}" \
  --expiry-slot "${EXPIRY_SLOT_B}" \
  --solver "${SOLVER_B_PUBKEY}" \
  --receiver-tag "${RECEIVER_TAG_B}" \
  --junocash-amount "${AMOUNT_B_ZAT}" \
  --creator-keypair "${CREATOR_KEYPAIR}" \
  --creator-source-token-account "${CREATOR_TA}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

echo "waiting for solver fill (B)..." >&2
wait_for_account "${FILL_B}" 120

if [[ "${SOLVER_B_UA}" != "${SOLVER_A_UA}" ]]; then
  echo "funding solver B so it can pay on JunoCash..." >&2
  fund_zat="$((AMOUNT_B_ZAT + 20000000))"
  fund_str="$(zat_to_junocash_amount "${fund_zat}")"
  recipients_fund="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${SOLVER_B_UA}" "${fund_str}")"
  opid_fund="$(retry 5 3 z_sendmany_opid "${USER_UA}" "${recipients_fund}" "${JUNOCASH_SEND_MINCONF}")"
  python3 - <<PY >/dev/null || { echo "solver funding op failed" >&2; exit 1; }
import json,subprocess,sys,time
opid='${opid_fund}'
for _ in range(1800):
  out=subprocess.check_output(['scripts/junocash/testnet/cli.sh','z_getoperationresult',f'["{opid}"]']).decode()
  try:
    items=json.loads(out)
  except Exception:
    time.sleep(1); continue
  if not items:
    time.sleep(1); continue
  it=items[0]
  if it.get('status')=='success':
    sys.exit(0)
  if it.get('status')=='failed':
    sys.exit(1)
  time.sleep(1)
sys.exit(1)
PY
  scripts/junocash/testnet/mine.sh "${JUNOCASH_SEND_MINCONF}" >/dev/null
fi

echo "sending JunoCash payment solver->user (amount=${PAYMENT_AMOUNT_B_STR})..." >&2
recipients_b="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${USER_UA}" "${PAYMENT_AMOUNT_B_STR}")"
opid_b="$(retry 5 3 z_sendmany_opid "${SOLVER_B_UA}" "${recipients_b}" "${JUNOCASH_SEND_MINCONF}")"
txid_b="$(
  python3 - <<PY
import json,subprocess,sys,time
opid='${opid_b}'
for _ in range(1800):
  out=subprocess.check_output(['scripts/junocash/testnet/cli.sh','z_getoperationresult',f'["{opid}"]']).decode()
  try:
    items=json.loads(out)
  except Exception:
    time.sleep(1); continue
  if not items:
    time.sleep(1); continue
  it=items[0]
  if it.get('status')=='success':
    print((it.get('result') or {}).get('txid',''))
    sys.exit(0)
  if it.get('status')=='failed':
    print(json.dumps(it)); sys.exit(1)
  time.sleep(1)
print('')
sys.exit(1)
PY
)" || { echo "sendmany op failed (B)" >&2; exit 1; }
echo "txid_b=${txid_b}" >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null
PAYMENT_HEIGHT_B="$(jcli getblockcount)"

echo "finding user note outindex (B)..." >&2
ACTION_B="$(
  jcli z_listunspent 1 9999999 false | python3 -c 'import json,sys
notes=json.load(sys.stdin)
txid=sys.argv[1].strip().lower()
acct=int(sys.argv[2])
for n in notes:
  if str(n.get("pool"))!="orchard":
    continue
  if str(n.get("txid","")).strip().lower()!=txid:
    continue
  if n.get("account")!=acct or not n.get("spendable"):
    continue
  print(n.get("outindex")); sys.exit(0)
sys.exit(1)
' "${txid_b}" "${USER_ACCOUNT}"
)" || { echo "failed to find action index (B)" >&2; exit 1; }

echo "generating witness (B, outgoing via solver ovk)..." >&2
wallet_backup_file_b="walletwitnessbdat"
rm -f "${DATA_DIR}/${wallet_backup_file_b}" >/dev/null 2>&1 || true
jcli backupwallet "${wallet_backup_file_b}" >/dev/null
WALLET_WITNESS_DAT_B="${DATA_DIR}/${wallet_backup_file_b}"
WITNESS_B="$(cd "${ROOT}" && cargo run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli scripts/junocash/testnet/cli.sh \
  --wallet "${WALLET_WITNESS_DAT_B}" \
  "${db_dump_flag[@]}" \
  --txid "${txid_b}" \
  --action "${ACTION_B}" \
  --unified-address "${SOLVER_B_UA}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_B_HEX}")"

INPUTS_B="$(JUNO_RECEIPT_WITNESS_HEX="${WITNESS_B}" "${GO_INTENTS}" receipt-inputs --json=false)"
AMOUNT_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^amount=([0-9]+)$/\1/p' | head -n 1)"
RECEIVER_TAG_B_WITNESS="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^receiver_tag=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
ORCHARD_ROOT_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^orchard_root=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
if [[ "${AMOUNT_B}" != "${AMOUNT_B_ZAT}" || "${RECEIVER_TAG_B_WITNESS}" != "${RECEIVER_TAG_B}" ]]; then
  echo "witness mismatch (B): amount/receiver_tag" >&2
  exit 1
fi

echo "publishing + finalizing CRP checkpoints (TEE operators)..." >&2
start_height="${PAYMENT_HEIGHT_A}"
if [[ "${PAYMENT_HEIGHT_B}" -lt "${start_height}" ]]; then start_height="${PAYMENT_HEIGHT_B}"; fi

for cid in "${NITRO_CID1}" "${NITRO_CID2}"; do
  "${GO_CRP}" run \
    --crp-program-id "${CRP_PROGRAM_ID}" \
    --deployment-id "${DEPLOYMENT_ID_HEX}" \
    --junocash-cli scripts/junocash/testnet/cli.sh \
    --junocash-chain "${JUNOCASH_CHAIN}" \
    --junocash-genesis-hash "${JUNOCASH_GENESIS_EXPECTED}" \
    --start-height "${start_height}" \
    --lag 1 \
    --poll-interval 1s \
    --payer-keypair "${SOLVER_KEYPAIR}" \
    --submit-operator-enclave-cid "${cid}" \
    --submit-operator-enclave-port "${NITRO_PORT}" \
    --priority-level "${PRIORITY_LEVEL}" \
    --once --submit-only >/dev/null
done

"${GO_CRP}" finalize-pending \
  --crp-program-id "${CRP_PROGRAM_ID}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --config-scan-limit 200 \
  --scan-limit 300 \
  --max-checkpoints 100 \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

echo "proving receipt bundles (Groth16)..." >&2
RAW_BUNDLE_A="$(risc0_prove_bundle risc0/receipt/host/Cargo.toml prove_bundle_v1 "${WITNESS_A}")"
BUNDLE_A="$(printf '%s\n' "${RAW_BUNDLE_A}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1 || true)"
if [[ -z "${BUNDLE_A}" ]]; then echo "failed to extract bundle hex (A)" >&2; exit 1; fi

RAW_BUNDLE_B="$(risc0_prove_bundle risc0/receipt/host/Cargo.toml prove_bundle_v1 "${WITNESS_B}")"
BUNDLE_B="$(printf '%s\n' "${RAW_BUNDLE_B}" | grep -E '^[0-9a-fA-F]+$' | tail -n 1 || true)"
if [[ -z "${BUNDLE_B}" ]]; then echo "failed to extract bundle hex (B)" >&2; exit 1; fi

echo "settling on Solana..." >&2
"${GO_INTENTS}" iep-settle \
  --deployment "${BASE_DEPLOYMENT}" \
  --deployment-file "${DEPLOYMENTS_FILE}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --crp-program-id "${CRP_PROGRAM_ID}" \
  --intent "${INTENT_A}" \
  --mint "${MINT}" \
  --recipient-token-account "${CREATOR_TA}" \
  --fee-token-account "${FEE_TA}" \
  --bundle-hex "${BUNDLE_A}" \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

"${GO_INTENTS}" iep-settle \
  --deployment "${BASE_DEPLOYMENT}" \
  --deployment-file "${DEPLOYMENTS_FILE}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --iep-program-id "${IEP_PROGRAM_ID}" \
  --crp-program-id "${CRP_PROGRAM_ID}" \
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
  out="$(spl-token -u "${SOLANA_RPC_URL}" balance --address "${token_account}" --output json-compact 2>/dev/null || true)"
  python3 -c 'import json,sys
raw=sys.stdin.read().strip()
obj=json.loads(raw)
print(str(obj.get("amount")))
' <<<"${out}"
}

echo "verifying balances..." >&2
creator_balance="$(spl_balance_amount "${CREATOR_TA}")"
solver_balance="$(spl_balance_amount "${SOLVER_TA}")"
solver2_balance="$(spl_balance_amount "${SOLVER2_TA}")"
fee_balance="$(spl_balance_amount "${FEE_TA}")"
echo "creator_balance=${creator_balance}" >&2
echo "solver_balance=${solver_balance}" >&2
echo "solver2_balance=${solver2_balance}" >&2
echo "fee_balance=${fee_balance}" >&2

echo "e2e ok" >&2
