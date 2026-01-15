#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DEPLOYMENT_FILE="deployments.json"
DEPLOYMENT_NAME=""

NET_AMOUNT_A="${JUNO_E2E_NET_AMOUNT_A:-1000}"
NET_AMOUNT_B="${JUNO_E2E_NET_AMOUNT_B:-1000}"
JUNOCASH_SEND_AMOUNT_A="${JUNO_E2E_JUNOCASH_SEND_AMOUNT_A:-1.0}"
JUNOCASH_SEND_AMOUNT_B="${JUNO_E2E_JUNOCASH_SEND_AMOUNT_B:-0.5}"

PRIORITY_LEVEL="${JUNO_E2E_PRIORITY_LEVEL:-Medium}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/e2e/devnet-testnet.sh --deployment <name> [--deployment-file <path>]

Environment (optional):
  JUNO_E2E_NET_AMOUNT_A            (default: 1000)
  JUNO_E2E_NET_AMOUNT_B            (default: 1000)
  JUNO_E2E_JUNOCASH_SEND_AMOUNT_A  (default: 1.0)
  JUNO_E2E_JUNOCASH_SEND_AMOUNT_B  (default: 0.5)
  JUNO_E2E_PRIORITY_LEVEL          (default: Medium)

Notes:
  - Starts a local JunoCash "testnet" Docker network (isolated, mined).
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

parse_spl_pubkey_json() {
  python3 - <<'PY'
import json,re,sys

def find_base58(x):
  if isinstance(x, str) and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", x):
    return x
  if isinstance(x, dict):
    for v in x.values():
      r=find_base58(v)
      if r:
        return r
  if isinstance(x, list):
    for v in x:
      r=find_base58(v)
      if r:
        return r
  return None

data=json.load(sys.stdin)
pk=find_base58(data)
if not pk:
  raise SystemExit("no base58 pubkey in JSON output")
print(pk)
PY
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
    sys.exit(0)
raise SystemExit("deployment not found")
PY
)"

DEPLOY_CLUSTER="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^cluster=(.+)$/\1/p' | head -n 1)"
SOLANA_RPC_URL="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^rpc_url=(.+)$/\1/p' | head -n 1)"
DEPLOYMENT_ID_HEX="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^deployment_id=(.+)$/\1/p' | head -n 1)"
FEE_BPS="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^fee_bps=(.+)$/\1/p' | head -n 1)"
FEE_COLLECTOR_PUBKEY="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^fee_collector=(.+)$/\1/p' | head -n 1)"

if [[ -z "${SOLANA_RPC_URL}" || -z "${DEPLOYMENT_ID_HEX}" || -z "${FEE_BPS}" || -z "${FEE_COLLECTOR_PUBKEY}" ]]; then
  echo "failed to parse deployment fields" >&2
  printf '%s\n' "${DEPLOY_INFO}" >&2
  exit 1
fi
if [[ "${DEPLOY_CLUSTER}" != "devnet" ]]; then
  echo "deployment must be devnet (got cluster=${DEPLOY_CLUSTER})" >&2
  exit 2
fi

export SOLANA_RPC_URL

ts="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="${ROOT}/tmp/e2e/devnet-testnet/${DEPLOYMENT_NAME}/${ts}"
mkdir -p "${WORKDIR}"

cleanup() {
  scripts/junocash/testnet/down.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "workdir: ${WORKDIR}" >&2
echo "deployment: ${DEPLOYMENT_NAME}" >&2
echo "solana_rpc_url: ${SOLANA_RPC_URL}" >&2

echo "building Go CLIs..." >&2
GO_INTENTS="${WORKDIR}/juno-intents"
GO_CRP="${WORKDIR}/crp-operator"
(cd "${ROOT}" && go build -o "${GO_INTENTS}" ./cmd/juno-intents)
(cd "${ROOT}" && go build -o "${GO_CRP}" ./cmd/crp-operator)

echo "creating Solana keypairs..." >&2
SOLVER_KEYPAIR="${WORKDIR}/solver.json"
CREATOR_KEYPAIR="${WORKDIR}/creator.json"
solana-keygen new --no-bip39-passphrase --silent --force -o "${SOLVER_KEYPAIR}"
solana-keygen new --no-bip39-passphrase --silent --force -o "${CREATOR_KEYPAIR}"
SOLVER_PUBKEY="$(solana-keygen pubkey "${SOLVER_KEYPAIR}")"
CREATOR_PUBKEY="$(solana-keygen pubkey "${CREATOR_KEYPAIR}")"
echo "solver_pubkey=${SOLVER_PUBKEY}" >&2
echo "creator_pubkey=${CREATOR_PUBKEY}" >&2

echo "funding Solana keypairs via devnet airdrop..." >&2
airdrop "${SOLVER_PUBKEY}" 2 "${SOLVER_KEYPAIR}"
airdrop "${CREATOR_PUBKEY}" 2 "${CREATOR_KEYPAIR}"

echo "creating SPL mint + token accounts..." >&2
MINT="$(spl-token -u "${SOLANA_RPC_URL}" create-token --decimals 0 --owner "${SOLVER_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact | parse_spl_pubkey_json)"
if [[ -z "${MINT}" ]]; then
  echo "failed to parse mint from spl-token output" >&2
  exit 1
fi

SOLVER_TA="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${SOLVER_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact | parse_spl_pubkey_json)"
CREATOR_TA="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${CREATOR_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact | parse_spl_pubkey_json)"
FEE_TA="$(spl-token -u "${SOLANA_RPC_URL}" create-account "${MINT}" --owner "${FEE_COLLECTOR_PUBKEY}" --fee-payer "${SOLVER_KEYPAIR}" --output json-compact | parse_spl_pubkey_json)"
for v in SOLVER_TA CREATOR_TA FEE_TA; do
  if [[ -z "${!v}" ]]; then
    echo "failed to parse ${v} from spl-token output" >&2
    exit 1
  fi
done

echo "minting tokens..." >&2
spl-token -u "${SOLANA_RPC_URL}" mint "${MINT}" 1000000 "${SOLVER_TA}" --mint-authority "${SOLVER_KEYPAIR}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null
spl-token -u "${SOLANA_RPC_URL}" mint "${MINT}" 1000000 "${CREATOR_TA}" --mint-authority "${SOLVER_KEYPAIR}" --fee-payer "${SOLVER_KEYPAIR}" >/dev/null

slot="$(solana -u "${SOLANA_RPC_URL}" slot | tr -d '\r\n ' )"
if [[ -z "${slot}" ]]; then
  echo "failed to fetch current slot" >&2
  exit 1
fi
EXPIRY_SLOT="$((slot + 5000))"
echo "expiry_slot=${EXPIRY_SLOT}" >&2

echo "starting JunoCash testnet docker harness..." >&2
scripts/junocash/testnet/up.sh >/dev/null

jcli() { scripts/junocash/testnet/cli.sh "$@"; }

echo "mining initial blocks for coinbase maturity..." >&2
scripts/junocash/testnet/mine.sh 110 >/dev/null

echo "creating JunoCash accounts + orchard UAs..." >&2
USER_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
SOLVER_ACCOUNT="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
USER_UA="$(jcli z_getaddressforaccount "${USER_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
SOLVER_UA="$(jcli z_getaddressforaccount "${SOLVER_ACCOUNT}" '["orchard"]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"
echo "user_account=${USER_ACCOUNT}" >&2
echo "solver_account=${SOLVER_ACCOUNT}" >&2
echo "user_ua=${USER_UA}" >&2
echo "solver_ua=${SOLVER_UA}" >&2

echo "shielding coinbase to user orchard UA..." >&2
opid="$(jcli z_shieldcoinbase "*" "${USER_UA}" null 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["opid"])')"

echo "waiting for shield operation..." >&2
txid_shield=""
for _ in $(seq 1 1800); do
  res="$(jcli z_getoperationresult "[\"${opid}\"]" 2>/dev/null || true)"
  compact="$(printf '%s' "${res}" | tr -d ' \n\r\t')"
  if [[ "${compact}" == "[]" ]]; then
    sleep 1
    continue
  fi
  txid_shield="$(printf '%s' "${res}" | python3 -c 'import json,sys; it=json.load(sys.stdin)[0]; print(it.get("result",{}).get("txid",""))')"
  break
done
if [[ -z "${txid_shield}" ]]; then
  echo "shielding operation did not complete" >&2
  jcli z_getoperationstatus "[\"${opid}\"]" >&2 || true
  exit 1
fi

echo "mining block to include shield tx..." >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null

echo "waiting for orchard note to be spendable..." >&2
for _ in $(seq 1 120); do
  if jcli z_listunspent 1 9999999 false | python3 -c "import json,sys; notes=json.load(sys.stdin); ok=any(n.get('pool')=='orchard' and n.get('spendable') and n.get('account')==${USER_ACCOUNT} for n in notes); sys.exit(0 if ok else 1)"; then
    break
  fi
  sleep 1
done

DATA_DIR="${JUNO_TESTNET_DATA_DIR_A:-tmp/junocash-testnet-a}"
wallet_candidates=(
  "${DATA_DIR}/wallet.dat"
  "${DATA_DIR}/testnet3/wallet.dat"
  "${DATA_DIR}/wallets/wallet.dat"
  "${DATA_DIR}/testnet3/wallets/wallet.dat"
)
WALLET_DAT=""
for p in "${wallet_candidates[@]}"; do
  if [[ -f "${ROOT}/${p}" ]]; then
    WALLET_DAT="${ROOT}/${p}"
    break
  fi
done
if [[ -z "${WALLET_DAT}" ]]; then
  echo "wallet.dat not found under ${DATA_DIR}" >&2
  exit 1
fi
echo "wallet_dat=${WALLET_DAT}" >&2

echo "=== Direction A (JunoCash -> Solana) ===" >&2

create_intent_a_raw="$("${GO_INTENTS}" iep-create-intent \
  --deployment "${DEPLOYMENT_NAME}" \
  --mint "${MINT}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --net-amount "${NET_AMOUNT_A}" \
  --expiry-slot "${EXPIRY_SLOT}" \
  --direction A \
  --creator-keypair "${CREATOR_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" \
  2>&1)"
INTENT_A="$(printf '%s\n' "${create_intent_a_raw}" | sed -nE 's/^intent=([1-9A-HJ-NP-Za-km-z]+)$/\1/p' | head -n 1)"
if [[ -z "${INTENT_A}" ]]; then
  echo "failed to parse intent A" >&2
  printf '%s\n' "${create_intent_a_raw}" >&2
  exit 1
fi
echo "intent_a=${INTENT_A}" >&2

FILL_ID_A="$("${GO_INTENTS}" iep-pdas --deployment "${DEPLOYMENT_NAME}" --intent "${INTENT_A}" --print fill-id-hex)"
echo "fill_id_a=${FILL_ID_A}" >&2

echo "sending JunoCash payment user->solver (amount=${JUNOCASH_SEND_AMOUNT_A})..." >&2
recipients_a="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${SOLVER_UA}" "${JUNOCASH_SEND_AMOUNT_A}")"
opid_a="$(jcli z_sendmany "${USER_UA}" "${recipients_a}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["opid"])')"

echo "waiting for sendmany operation (A)..." >&2
txid_a=""
for _ in $(seq 1 1800); do
  res="$(jcli z_getoperationresult "[\"${opid_a}\"]" 2>/dev/null || true)"
  compact="$(printf '%s' "${res}" | tr -d ' \n\r\t')"
  if [[ "${compact}" == "[]" ]]; then
    sleep 1
    continue
  fi
  txid_a="$(printf '%s' "${res}" | python3 -c 'import json,sys; it=json.load(sys.stdin)[0]; print(it.get("result",{}).get("txid",""))')"
  break
done
if [[ -z "${txid_a}" ]]; then
  echo "sendmany op did not complete (A)" >&2
  exit 1
fi
echo "txid_a=${txid_a}" >&2

height_a_before="$(jcli getblockcount)"
echo "mining block to include payment tx (A)..." >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null
height_a_after="$(jcli getblockcount)"
PAYMENT_HEIGHT_A="${height_a_after}"
echo "payment_height_a=${PAYMENT_HEIGHT_A} (before=${height_a_before} after=${height_a_after})" >&2

echo "waiting for solver orchard note to appear (A)..." >&2
ACTION_A=""
for _ in $(seq 1 120); do
  ACTION_A="$(jcli z_listunspent 1 9999999 false | python3 - "${txid_a}" "${SOLVER_ACCOUNT}" <<'PY'
import json,sys
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
PY
)" && break || true
  sleep 1
done
if [[ -z "${ACTION_A}" ]]; then
  echo "failed to find solver note outindex for tx A" >&2
  exit 1
fi
echo "action_a=${ACTION_A}" >&2

echo "generating receipt witness (A)..." >&2
WITNESS_A="$(cd "${ROOT}" && cargo run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli scripts/junocash/testnet/cli.sh \
  --wallet "${WALLET_DAT}" \
  --txid "${txid_a}" \
  --action "${ACTION_A}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_A}")"

INPUTS_A="$("${GO_INTENTS}" receipt-inputs --witness-hex "${WITNESS_A}" --json=false)"
AMOUNT_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^amount=([0-9]+)$/\1/p' | head -n 1)"
RECEIVER_TAG_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^receiver_tag=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
ORCHARD_ROOT_A="$(printf '%s\n' "${INPUTS_A}" | sed -nE 's/^orchard_root=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
echo "orchard_root_a=${ORCHARD_ROOT_A}" >&2
echo "receiver_tag_a=${RECEIVER_TAG_A}" >&2
echo "junocash_amount_a_zat=${AMOUNT_A}" >&2

echo "mining 1 extra block (reorg safety)..." >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null

echo "=== Direction B (Solana -> JunoCash) ===" >&2

create_intent_b_raw="$("${GO_INTENTS}" iep-create-intent \
  --deployment "${DEPLOYMENT_NAME}" \
  --mint "${MINT}" \
  --solana-recipient "${CREATOR_PUBKEY}" \
  --net-amount "${NET_AMOUNT_B}" \
  --expiry-slot "${EXPIRY_SLOT}" \
  --direction B \
  --creator-keypair "${CREATOR_KEYPAIR}" \
  --creator-source-token-account "${CREATOR_TA}" \
  --priority-level "${PRIORITY_LEVEL}" \
  2>&1)"
INTENT_B="$(printf '%s\n' "${create_intent_b_raw}" | sed -nE 's/^intent=([1-9A-HJ-NP-Za-km-z]+)$/\1/p' | head -n 1)"
if [[ -z "${INTENT_B}" ]]; then
  echo "failed to parse intent B" >&2
  printf '%s\n' "${create_intent_b_raw}" >&2
  exit 1
fi
echo "intent_b=${INTENT_B}" >&2

FILL_ID_B="$("${GO_INTENTS}" iep-pdas --deployment "${DEPLOYMENT_NAME}" --intent "${INTENT_B}" --print fill-id-hex)"
echo "fill_id_b=${FILL_ID_B}" >&2

echo "sending JunoCash payment solver->user (amount=${JUNOCASH_SEND_AMOUNT_B})..." >&2
recipients_b="$(python3 -c 'import json,sys; addr=sys.argv[1]; amt=sys.argv[2]; print(json.dumps([{"address":addr,"amount":float(amt)}]))' "${USER_UA}" "${JUNOCASH_SEND_AMOUNT_B}")"
opid_b="$(jcli z_sendmany "${SOLVER_UA}" "${recipients_b}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["opid"])')"

echo "waiting for sendmany operation (B)..." >&2
txid_b=""
for _ in $(seq 1 1800); do
  res="$(jcli z_getoperationresult "[\"${opid_b}\"]" 2>/dev/null || true)"
  compact="$(printf '%s' "${res}" | tr -d ' \n\r\t')"
  if [[ "${compact}" == "[]" ]]; then
    sleep 1
    continue
  fi
  txid_b="$(printf '%s' "${res}" | python3 -c 'import json,sys; it=json.load(sys.stdin)[0]; print(it.get("result",{}).get("txid",""))')"
  break
done
if [[ -z "${txid_b}" ]]; then
  echo "sendmany op did not complete (B)" >&2
  exit 1
fi
echo "txid_b=${txid_b}" >&2

height_b_before="$(jcli getblockcount)"
echo "mining block to include payment tx (B)..." >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null
height_b_after="$(jcli getblockcount)"
PAYMENT_HEIGHT_B="${height_b_after}"
echo "payment_height_b=${PAYMENT_HEIGHT_B} (before=${height_b_before} after=${height_b_after})" >&2

echo "waiting for user orchard note to appear (B)..." >&2
ACTION_B=""
for _ in $(seq 1 120); do
  ACTION_B="$(jcli z_listunspent 1 9999999 false | python3 - "${txid_b}" "${USER_ACCOUNT}" <<'PY'
import json,sys
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
PY
)" && break || true
  sleep 1
done
if [[ -z "${ACTION_B}" ]]; then
  echo "failed to find user note outindex for tx B" >&2
  exit 1
fi
echo "action_b=${ACTION_B}" >&2

echo "generating receipt witness (B, outgoing via solver ovk)..." >&2
WITNESS_B="$(cd "${ROOT}" && cargo run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli scripts/junocash/testnet/cli.sh \
  --wallet "${WALLET_DAT}" \
  --txid "${txid_b}" \
  --action "${ACTION_B}" \
  --unified-address "${SOLVER_UA}" \
  --deployment-id "${DEPLOYMENT_ID_HEX}" \
  --fill-id "${FILL_ID_B}")"

INPUTS_B="$("${GO_INTENTS}" receipt-inputs --witness-hex "${WITNESS_B}" --json=false)"
AMOUNT_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^amount=([0-9]+)$/\1/p' | head -n 1)"
RECEIVER_TAG_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^receiver_tag=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
ORCHARD_ROOT_B="$(printf '%s\n' "${INPUTS_B}" | sed -nE 's/^orchard_root=([0-9a-fA-F]+)$/\1/p' | head -n 1)"
echo "orchard_root_b=${ORCHARD_ROOT_B}" >&2
echo "receiver_tag_b=${RECEIVER_TAG_B}" >&2
echo "junocash_amount_b_zat=${AMOUNT_B}" >&2

echo "mining 1 extra block (reorg safety)..." >&2
scripts/junocash/testnet/mine.sh 1 >/dev/null

echo "finalizing CRP checkpoints (run-mode, chain verified)..." >&2
genesis="$(jcli getblockhash 0 | tr -d '\" \r\n')"
chain="$(jcli getblockchaininfo | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chain",""))')"
echo "junocash_chain=${chain}" >&2
echo "junocash_genesis=${genesis}" >&2

start_height="${PAYMENT_HEIGHT_A}"
if [[ "${PAYMENT_HEIGHT_B}" -lt "${start_height}" ]]; then
  start_height="${PAYMENT_HEIGHT_B}"
fi

"${GO_CRP}" run \
  --deployment "${DEPLOYMENT_NAME}" \
  --deployment-file "${DEPLOYMENT_FILE}" \
  --junocash-cli scripts/junocash/testnet/cli.sh \
  --junocash-chain testnet \
  --junocash-genesis-hash "${genesis}" \
  --start-height "${start_height}" \
  --lag 1 \
  --poll-interval 1s \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --submit-operator-keypair "${SOLVER_KEYPAIR}" \
  --finalize-operator-keypair "${SOLVER_KEYPAIR}" \
  --finalize-operator-keypair "${CREATOR_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" \
  --once >/dev/null

echo "filling intents on Solana..." >&2
"${GO_INTENTS}" iep-fill \
  --deployment "${DEPLOYMENT_NAME}" \
  --intent "${INTENT_A}" \
  --mint "${MINT}" \
  --receiver-tag "${RECEIVER_TAG_A}" \
  --junocash-amount "${AMOUNT_A}" \
  --solver-keypair "${SOLVER_KEYPAIR}" \
  --solver-source-token-account "${SOLVER_TA}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

"${GO_INTENTS}" iep-fill \
  --deployment "${DEPLOYMENT_NAME}" \
  --intent "${INTENT_B}" \
  --mint "${MINT}" \
  --receiver-tag "${RECEIVER_TAG_B}" \
  --junocash-amount "${AMOUNT_B}" \
  --solver-keypair "${SOLVER_KEYPAIR}" \
  --solver-destination-token-account "${SOLVER_TA}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

echo "proving Groth16 bundles (CUDA)..." >&2
BUNDLE_A="$(cd "${ROOT}" && cargo run --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --bin prove_bundle_v1 -- --witness-hex "${WITNESS_A}")"
BUNDLE_B="$(cd "${ROOT}" && cargo run --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --bin prove_bundle_v1 -- --witness-hex "${WITNESS_B}")"

echo "settling on Solana..." >&2
"${GO_INTENTS}" iep-settle \
  --deployment "${DEPLOYMENT_NAME}" \
  --intent "${INTENT_A}" \
  --mint "${MINT}" \
  --recipient-token-account "${CREATOR_TA}" \
  --fee-token-account "${FEE_TA}" \
  --bundle-hex "${BUNDLE_A}" \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

"${GO_INTENTS}" iep-settle \
  --deployment "${DEPLOYMENT_NAME}" \
  --intent "${INTENT_B}" \
  --mint "${MINT}" \
  --recipient-token-account "${SOLVER_TA}" \
  --fee-token-account "${FEE_TA}" \
  --bundle-hex "${BUNDLE_B}" \
  --payer-keypair "${SOLVER_KEYPAIR}" \
  --priority-level "${PRIORITY_LEVEL}" >/dev/null

echo "verifying balances..." >&2
echo "creator_balance=$(spl-token -u "${SOLANA_RPC_URL}" balance "${CREATOR_TA}" --output json-compact | python3 -c 'import json,sys; print(json.load(sys.stdin).get("amount",""))')" >&2
echo "solver_balance=$(spl-token -u "${SOLANA_RPC_URL}" balance "${SOLVER_TA}" --output json-compact | python3 -c 'import json,sys; print(json.load(sys.stdin).get("amount",""))')" >&2
echo "fee_balance=$(spl-token -u "${SOLANA_RPC_URL}" balance "${FEE_TA}" --output json-compact | python3 -c 'import json,sys; print(json.load(sys.stdin).get("amount",""))')" >&2

echo "e2e ok" >&2
