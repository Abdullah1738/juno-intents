#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

CLUSTER=""
RPC_URL="${SOLANA_RPC_URL:-}"
REFUND_PUBKEY=""
WORKDIR_OVERRIDE=""
SELECTOR="${JUNO_RISC0_SELECTOR:-JINT}"

SKIP_BUILD="false"
SKIP_FUNDING_WAIT="false"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/solana/deploy-risc0-verifier.sh \
    --cluster devnet|mainnet|localnet \
    --refund-to <pubkey> \
    [--rpc-url <url>] \
    [--selector JINT] \
    [--workdir <path>] \
    [--skip-build]
    [--skip-funding-wait]

Notes:
  - Deploys a Verifier Router + Groth16 verifier program, then initializes:
      - router PDA = PDA("router")
      - verifier entry PDA = PDA("verifier", selector)
  - Router program is deployed immutable (--final).
  - Groth16 verifier program is deployed with upgrade authority = router PDA.
  - The RISC0 Solana verifier programs are Anchor programs which hard-code their program id.
    This script stages a private copy of the upstream sources under tmp/ and patches `declare_id!()`
    to match the generated program ids before building.
  - Creates a fresh disposable payer keypair under tmp/ and deletes it on success.
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
    --refund-to)
      REFUND_PUBKEY="${2:-}"; shift 2 ;;
    --selector)
      SELECTOR="${2:-}"; shift 2 ;;
    --workdir)
      WORKDIR_OVERRIDE="${2:-}"; shift 2 ;;
    --skip-build)
      SKIP_BUILD="true"; shift 1 ;;
    --skip-funding-wait)
      SKIP_FUNDING_WAIT="true"; shift 1 ;;
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
if [[ -z "${REFUND_PUBKEY}" ]]; then
  echo "--refund-to is required" >&2
  exit 2
fi
if [[ -z "${SELECTOR}" ]]; then
  echo "--selector is required" >&2
  exit 2
fi
if [[ "${#SELECTOR}" -ne 4 ]]; then
  echo "--selector must be 4 ascii bytes (e.g. JINT)" >&2
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
if ! command -v python3 >/dev/null; then
  echo "python3 not found in PATH" >&2
  exit 1
fi
if [[ "${SKIP_BUILD}" != "true" ]] && ! command -v cargo >/dev/null; then
  echo "cargo not found in PATH (required unless --skip-build)" >&2
  exit 1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -n "${WORKDIR_OVERRIDE}" ]]; then
  WORKDIR="${WORKDIR_OVERRIDE}"
else
  WORKDIR="${ROOT}/tmp/solana/risc0-verifier/${ts}"
fi
mkdir -p "${WORKDIR}"

PAYER_KEYPAIR="${WORKDIR}/payer.json"
VR_KEYPAIR="${WORKDIR}/verifier-router-program.json"
G16_KEYPAIR="${WORKDIR}/groth16-verifier-program.json"

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
if [[ ! -f "${PAYER_KEYPAIR}" ]]; then
  solana-keygen new --no-bip39-passphrase --silent --force -o "${PAYER_KEYPAIR}"
fi
PAYER_PUBKEY="$(solana-keygen pubkey "${PAYER_KEYPAIR}")"
echo "payer: ${PAYER_PUBKEY}" >&2

if [[ ! -f "${VR_KEYPAIR}" ]]; then
  solana-keygen new --no-bip39-passphrase --silent --force -o "${VR_KEYPAIR}"
fi
if [[ ! -f "${G16_KEYPAIR}" ]]; then
  solana-keygen new --no-bip39-passphrase --silent --force -o "${G16_KEYPAIR}"
fi

VR_PROGRAM_ID="$(solana-keygen pubkey "${VR_KEYPAIR}")"
G16_PROGRAM_ID="$(solana-keygen pubkey "${G16_KEYPAIR}")"
echo "verifier_router_program_id: ${VR_PROGRAM_ID}" >&2
echo "groth16_verifier_program_id: ${G16_PROGRAM_ID}" >&2

BUILD_SRC="${WORKDIR}/risc0-solana"

patch_declare_id() {
  local file="$1"
  local new_id="$2"
  python3 - "${file}" "${new_id}" <<'PY'
import re
import sys

path = sys.argv[1]
new_id = sys.argv[2]

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

out = []
patched = False
for line in lines:
    if re.match(r'\s*declare_id!\("[^"]+"\);\s*$', line):
        out.append(re.sub(r'declare_id!\("[^"]+"\);', f'declare_id!("{new_id}");', line))
        patched = True
    else:
        out.append(line)

if not patched:
    raise SystemExit(f"declare_id!() not found in {path}")

with open(path, "w", encoding="utf-8") as f:
    f.write("".join(out))
PY
}

if [[ ! -d "${BUILD_SRC}" ]]; then
  echo "staging risc0-solana sources..." >&2
  cp -a "${ROOT}/third_party/risc0/risc0-solana" "${BUILD_SRC}"
  rm -rf "${BUILD_SRC}/solana-verifier/target" >/dev/null 2>&1 || true
  patch_declare_id "${BUILD_SRC}/solana-verifier/programs/verifier_router/src/lib.rs" "${VR_PROGRAM_ID}"
  patch_declare_id "${BUILD_SRC}/solana-verifier/programs/groth_16_verifier/src/lib.rs" "${G16_PROGRAM_ID}"
fi

if [[ "${SKIP_BUILD}" != "true" ]]; then
  echo "building verifier_router (INITIAL_OWNER=${PAYER_PUBKEY})..." >&2
  (cd "${BUILD_SRC}" && INITIAL_OWNER="${PAYER_PUBKEY}" cargo build-sbf --manifest-path solana-verifier/programs/verifier_router/Cargo.toml)
  echo "building groth_16_verifier..." >&2
  (cd "${BUILD_SRC}" && cargo build-sbf --manifest-path solana-verifier/programs/groth_16_verifier/Cargo.toml)
fi

VR_SO="${BUILD_SRC}/solana-verifier/target/deploy/verifier_router.so"
G16_SO="${BUILD_SRC}/solana-verifier/target/deploy/groth_16_verifier.so"
for f in "${VR_SO}" "${G16_SO}"; do
  if [[ ! -f "${f}" ]]; then
    echo "missing program artifact: ${f}" >&2
    exit 1
  fi
done

echo "estimating required SOL..." >&2
vr_bytes="$(wc -c <"${VR_SO}" | tr -d ' ')"
g16_bytes="$(wc -c <"${G16_SO}" | tr -d ' ')"

estimate_rent_exempt() {
  local bytes="$1"
  local out
  out="$(solana -u "${RPC_URL}" rent --lamports "${bytes}" 2>/dev/null || true)"
  echo "${out}" | awk '/Rent-exempt minimum:/ {print $3; exit}' || true
}

rent_vr="$(estimate_rent_exempt "$((vr_bytes + 2048))")"
rent_g16="$(estimate_rent_exempt "$((g16_bytes + 2048))")"

need_lamports="0"
if [[ -n "${rent_vr}" && -n "${rent_g16}" ]]; then
  # sum(rent) + max(rent) + 0.5 SOL
  sum_rent="$((rent_vr + rent_g16))"
  max_rent="${rent_vr}"
  if [[ "${rent_g16}" -gt "${max_rent}" ]]; then max_rent="${rent_g16}"; fi
  need_lamports="$(( sum_rent + max_rent + 500000000 ))"
else
  need_lamports="$(( 6 * 1000000000 ))"
  echo "warning: could not parse solana rent output; using conservative default: 6 SOL" >&2
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
    echo "airdropping 1 SOL..." >&2
    solana -u "${RPC_URL}" airdrop 1 "${PAYER_PUBKEY}" --keypair "${PAYER_KEYPAIR}" || true
    sleep 2
  done
}

airdrop_if_possible || true

if [[ "${SKIP_FUNDING_WAIT}" != "true" ]]; then
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
else
  bal="$(get_balance_lamports)"
  echo "skip funding wait: payer balance=${bal:-unknown} lamports (need=${need_lamports})" >&2
fi

echo "deploying verifier_router..." >&2
solana -u "${RPC_URL}" program deploy "${VR_SO}" \
  --keypair "${PAYER_KEYPAIR}" \
  --program-id "${VR_KEYPAIR}" \
  --upgrade-authority "${PAYER_KEYPAIR}"

echo "deploying groth_16_verifier..." >&2
solana -u "${RPC_URL}" program deploy "${G16_SO}" \
  --keypair "${PAYER_KEYPAIR}" \
  --program-id "${G16_KEYPAIR}" \
  --upgrade-authority "${PAYER_KEYPAIR}"

echo "finalizing verifier_router program (immutable)..." >&2
solana -u "${RPC_URL}" program set-upgrade-authority "${VR_PROGRAM_ID}" --final --keypair "${PAYER_KEYPAIR}"

echo "deriving router PDAs..." >&2
ROUTER_PDA="$(cd "${ROOT}" && go run ./cmd/juno-intents risc0-pda --verifier-router-program-id "${VR_PROGRAM_ID}" --selector "${SELECTOR}" --print router)"
ENTRY_PDA="$(cd "${ROOT}" && go run ./cmd/juno-intents risc0-pda --verifier-router-program-id "${VR_PROGRAM_ID}" --selector "${SELECTOR}" --print verifier-entry)"
echo "router_pda: ${ROUTER_PDA}" >&2
echo "verifier_entry_pda: ${ENTRY_PDA}" >&2

echo "setting groth_16_verifier upgrade authority to router PDA..." >&2
solana -u "${RPC_URL}" program set-upgrade-authority "${G16_PROGRAM_ID}" \
  --new-upgrade-authority "${ROUTER_PDA}" \
  --skip-new-upgrade-authority-signer-check \
  --keypair "${PAYER_KEYPAIR}"

echo "initializing router PDA + registering verifier selector ${SELECTOR}..." >&2
(cd "${ROOT}" && SOLANA_RPC_URL="${RPC_URL}" go run ./cmd/juno-intents init-risc0-verifier \
  --verifier-router-program-id "${VR_PROGRAM_ID}" \
  --verifier-program-id "${G16_PROGRAM_ID}" \
  --selector "${SELECTOR}" \
  --payer-keypair "${PAYER_KEYPAIR}") >/dev/null

echo "refunding remaining balance to ${REFUND_PUBKEY} (best-effort)..." >&2
solana -u "${RPC_URL}" transfer "${REFUND_PUBKEY}" ALL --allow-unfunded-recipient --keypair "${PAYER_KEYPAIR}" >/dev/null 2>&1 || true

echo "export these for scripts/solana/deploy.sh:" >&2
echo "  --verifier-router-program ${VR_PROGRAM_ID}" >&2
echo "  --verifier-program ${G16_PROGRAM_ID}" >&2
echo "done" >&2
