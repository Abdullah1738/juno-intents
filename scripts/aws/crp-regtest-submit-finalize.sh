#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Pin to a concrete AL2023 AMI (us-east-1) for repeatable tooling.
AMI_ID="${JUNO_NITRO_SMOKE_AMI_ID:-ami-07ff62358b87c7116}"
INSTANCE_TYPE="${JUNO_NITRO_SMOKE_INSTANCE_TYPE:-c6i.xlarge}"

DEPLOYMENT_FILE="deployments.json"
DEPLOYMENT_NAME=""

RELEASE_REPO="${JUNO_NITRO_EIF_RELEASE_REPO:-Abdullah1738/juno-intents}"
RELEASE_TAG="${JUNO_NITRO_EIF_RELEASE_TAG:-}"

OP1_SEALED_KEY_FILE=""
OP2_SEALED_KEY_FILE=""

KMS_KEY_ID="${JUNO_NITRO_KMS_KEY_ID:-alias/juno-intents-nitro-operator}"
KMS_VSOCK_PORT="${JUNO_NITRO_KMS_VSOCK_PORT:-8000}"
ENCLAVE_CID="${JUNO_NITRO_ENCLAVE_CID:-16}"
ENCLAVE_PORT="${JUNO_NITRO_ENCLAVE_PORT:-5000}"
ENCLAVE_MEM_MIB="${JUNO_NITRO_ENCLAVE_MEM_MIB:-1024}"
ENCLAVE_CPU_COUNT="${JUNO_NITRO_ENCLAVE_CPU_COUNT:-2}"

INSTANCE_PROFILE_NAME="${JUNO_NITRO_INSTANCE_PROFILE_NAME:-}"

LAG="${JUNO_CRP_REGTEST_LAG:-1}"
MINE_BLOCKS="${JUNO_CRP_REGTEST_MINE_BLOCKS:-3}"

CONFIG_SCAN_LIMIT="${JUNO_CRP_CONFIG_SCAN_LIMIT:-200}"
CHECKPOINT_SCAN_LIMIT="${JUNO_CRP_CHECKPOINT_SCAN_LIMIT:-200}"
SSM_TIMEOUT_SECONDS="${JUNO_SSM_TIMEOUT_SECONDS:-7200}"

PAYER_KEYPAIR_FILE=""

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/crp-regtest-submit-finalize.sh \
    --deployment <name> \
    --eif-release-tag <tag> \
    --operator1-sealed-key <path> \
    --operator2-sealed-key <path> \
    [--payer-keypair <path>]

Environment:
  JUNO_AWS_REGION                    (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME            (default: runs-on)
  JUNO_NITRO_SMOKE_AMI_ID            (default: pinned AL2023 us-east-1)
  JUNO_NITRO_SMOKE_INSTANCE_TYPE     (default: c6i.xlarge)
  JUNO_NITRO_INSTANCE_PROFILE_NAME   (default: terraform output instance_profile_name, else juno-intents-nitro-operator)

  JUNO_NITRO_EIF_RELEASE_REPO        (default: Abdullah1738/juno-intents)
  JUNO_NITRO_EIF_RELEASE_TAG         (required)

  JUNO_NITRO_KMS_KEY_ID              (default: alias/juno-intents-nitro-operator)
  JUNO_NITRO_KMS_VSOCK_PORT          (default: 8000)
  JUNO_NITRO_ENCLAVE_CID             (default: 16)
  JUNO_NITRO_ENCLAVE_PORT            (default: 5000)
  JUNO_NITRO_ENCLAVE_MEM_MIB         (default: 1024)
  JUNO_NITRO_ENCLAVE_CPU_COUNT       (default: 2)

  JUNO_CRP_REGTEST_LAG               (default: 1)
  JUNO_CRP_REGTEST_MINE_BLOCKS       (default: 3; must be > lag)
  JUNO_CRP_CONFIG_SCAN_LIMIT         (default: 200)
  JUNO_CRP_CHECKPOINT_SCAN_LIMIT     (default: 200)
  JUNO_SSM_TIMEOUT_SECONDS           (default: 7200)

Notes:
  - Uses a single enclave host instance to submit the same checkpoint twice (two operator sealed keys), then finalizes via finalize-pending.
  - Runs a local junocash regtest (Docker) inside the EC2 instance.
  - If --payer-keypair is not provided, generates a fresh devnet payer and funds it via scripts/aws/devnet-airdrop.sh.
  - All AWS calls use: --profile juno
  - The instance is ALWAYS terminated on exit (success/failure).
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
    --eif-release-tag)
      RELEASE_TAG="${2:-}"; shift 2 ;;
    --eif-release-repo)
      RELEASE_REPO="${2:-}"; shift 2 ;;
    --operator1-sealed-key)
      OP1_SEALED_KEY_FILE="${2:-}"; shift 2 ;;
    --operator2-sealed-key)
      OP2_SEALED_KEY_FILE="${2:-}"; shift 2 ;;
    --payer-keypair)
      PAYER_KEYPAIR_FILE="${2:-}"; shift 2 ;;
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
if [[ -z "${RELEASE_TAG}" ]]; then
  echo "--eif-release-tag is required" >&2
  exit 2
fi
if [[ -z "${OP1_SEALED_KEY_FILE}" || -z "${OP2_SEALED_KEY_FILE}" ]]; then
  echo "--operator1-sealed-key and --operator2-sealed-key are required" >&2
  exit 2
fi
if [[ "${MINE_BLOCKS}" -le "${LAG}" ]]; then
  echo "JUNO_CRP_REGTEST_MINE_BLOCKS must be > JUNO_CRP_REGTEST_LAG (mine_blocks=${MINE_BLOCKS} lag=${LAG})" >&2
  exit 2
fi

if ! command -v terraform >/dev/null; then
  echo "missing required command: terraform" >&2
  exit 1
fi
if ! command -v aws >/dev/null; then
  echo "missing required command: aws" >&2
  exit 1
fi

if [[ ! -f "${DEPLOYMENT_FILE}" ]]; then
  echo "deployment file not found: ${DEPLOYMENT_FILE}" >&2
  exit 1
fi

DEPLOYMENTS_JSON_B64="$(python3 - "${DEPLOYMENT_FILE}" <<'PY'
import base64,sys
path=sys.argv[1]
with open(path,"rb") as f:
  print(base64.b64encode(f.read()).decode("ascii"))
PY
)"

DEPLOY_INFO="$(
  python3 - "${DEPLOYMENT_FILE}" "${DEPLOYMENT_NAME}" <<'PY'
import json,sys
path=sys.argv[1]
name=sys.argv[2]
with open(path,"r",encoding="utf-8") as f:
  d=json.load(f)
items=d.get("deployments") or []
for it in items:
  if it.get("name")==name:
    print("cluster="+str(it.get("cluster","")).strip())
    print("rpc_url="+str(it.get("rpc_url","")).strip())
    sys.exit(0)
raise SystemExit("deployment not found")
PY
)"
DEPLOY_CLUSTER="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^cluster=(.+)$/\1/p' | head -n 1)"
DEPLOY_RPC_URL="$(printf '%s\n' "${DEPLOY_INFO}" | sed -nE 's/^rpc_url=(.+)$/\1/p' | head -n 1)"

if [[ -z "${DEPLOY_CLUSTER}" || -z "${DEPLOY_RPC_URL}" ]]; then
  echo "failed to parse cluster/rpc_url for deployment: ${DEPLOYMENT_NAME}" >&2
  exit 1
fi
if [[ "${DEPLOY_CLUSTER}" != "devnet" ]]; then
  echo "this smoke test currently requires a devnet deployment (got cluster=${DEPLOY_CLUSTER})" >&2
  exit 2
fi

OP1_EXPECTED="$(basename "${OP1_SEALED_KEY_FILE}")"
OP1_EXPECTED="${OP1_EXPECTED%.sealed.json}"
OP2_EXPECTED="$(basename "${OP2_SEALED_KEY_FILE}")"
OP2_EXPECTED="${OP2_EXPECTED%.sealed.json}"

OP1_SEALED_B64="$(python3 - "${OP1_SEALED_KEY_FILE}" <<'PY'
import base64,sys
path=sys.argv[1]
with open(path,"rb") as f:
  print(base64.b64encode(f.read()).decode("ascii"))
PY
)"
OP2_SEALED_B64="$(python3 - "${OP2_SEALED_KEY_FILE}" <<'PY'
import base64,sys
path=sys.argv[1]
with open(path,"rb") as f:
  print(base64.b64encode(f.read()).decode("ascii"))
PY
)"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
WORKDIR="${ROOT}/tmp/aws/crp-regtest-smoke/${ts}"
mkdir -p "${WORKDIR}"

if [[ -z "${PAYER_KEYPAIR_FILE}" ]]; then
  if ! command -v go >/dev/null; then
    echo "missing required command: go (needed to generate payer keypair)" >&2
    exit 1
  fi
  PAYER_KEYPAIR_FILE="${WORKDIR}/payer.json"
  echo "generating devnet payer keypair..." >&2
  KEYGEN_OUT="$(go run ./cmd/juno-intents keygen --out "${PAYER_KEYPAIR_FILE}" --force)"
  PAYER_PUBKEY="$(printf '%s\n' "${KEYGEN_OUT}" | sed -nE 's/^pubkey_base58=(.+)$/\1/p' | head -n 1)"
  if [[ -z "${PAYER_PUBKEY}" ]]; then
    echo "failed to parse payer pubkey from keygen output" >&2
    printf '%s\n' "${KEYGEN_OUT}" >&2
    exit 1
  fi
  echo "payer_pubkey=${PAYER_PUBKEY}" >&2

  echo "funding payer via devnet airdrop..." >&2
  scripts/aws/devnet-airdrop.sh --pubkey "${PAYER_PUBKEY}" --sol 1 --rpc-url "${DEPLOY_RPC_URL}" >/dev/null
else
  if [[ ! -f "${PAYER_KEYPAIR_FILE}" ]]; then
    echo "--payer-keypair not found: ${PAYER_KEYPAIR_FILE}" >&2
    exit 1
  fi
  echo "using existing payer keypair: ${PAYER_KEYPAIR_FILE}" >&2
fi

PAYER_JSON_B64="$(python3 - "${PAYER_KEYPAIR_FILE}" <<'PY'
import base64,sys
path=sys.argv[1]
with open(path,"rb") as f:
  print(base64.b64encode(f.read()).decode("ascii"))
PY
)"

awsj() {
  aws --profile "${PROFILE}" --region "${REGION}" "$@"
}

get_cf_output() {
  local key="$1"
  awsj cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='${key}'].OutputValue | [0]" \
    --output text
}

META_PATH="$(mktemp -t juno-nitro-operator-meta.XXXXXX.json)"
cleanup_meta() {
  rm -f "${META_PATH}" >/dev/null 2>&1 || true
}
trap cleanup_meta EXIT

echo "fetching operator.meta.json from GitHub release..." >&2
python3 - "${RELEASE_REPO}" "${RELEASE_TAG}" "${META_PATH}" <<'PY'
import sys
import urllib.request

repo = sys.argv[1]
tag = sys.argv[2]
path = sys.argv[3]
url = f"https://github.com/{repo}/releases/download/{tag}/operator.meta.json"

with urllib.request.urlopen(url, timeout=30) as r:
  data = r.read()

with open(path, "wb") as f:
  f.write(data)
print("ok", file=sys.stderr)
PY

KV_OUT="$(
  python3 - "${META_PATH}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
  meta = json.load(f)

git_sha = (meta.get("git_sha") or "").strip()
pcr0 = (meta.get("pcr0") or "").strip().lower()
eif_sha256 = (meta.get("eif_sha256") or "").strip().lower()

if len(git_sha) < 8:
  raise SystemExit("missing/invalid git_sha in operator.meta.json")
if len(pcr0) != 96:
  raise SystemExit("missing/invalid pcr0 in operator.meta.json")
if len(eif_sha256) != 64:
  raise SystemExit("missing/invalid eif_sha256 in operator.meta.json")

print(f"git_sha={git_sha}")
print(f"pcr0={pcr0}")
print(f"eif_sha256={eif_sha256}")
PY
)"

git_sha="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^git_sha=(.+)$/\1/p' | head -n 1)"
pcr0="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^pcr0=(.+)$/\1/p' | head -n 1)"
eif_sha256="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^eif_sha256=(.+)$/\1/p' | head -n 1)"

echo "git_sha=${git_sha}" >&2
echo "pcr0=${pcr0}" >&2
echo "eif_sha256=${eif_sha256}" >&2

echo "applying terraform allowed_pcr0..." >&2
terraform -chdir="${ROOT}/infra/terraform/nitro-operator" apply -auto-approve -var "allowed_pcr0=[\"${pcr0}\"]" >/dev/null

if [[ -z "${INSTANCE_PROFILE_NAME}" ]]; then
  INSTANCE_PROFILE_NAME="$(terraform -chdir="${ROOT}/infra/terraform/nitro-operator" output -raw instance_profile_name 2>/dev/null || true)"
fi
if [[ -z "${INSTANCE_PROFILE_NAME}" || "${INSTANCE_PROFILE_NAME}" == "null" ]]; then
  INSTANCE_PROFILE_NAME="juno-intents-nitro-operator"
fi

SUBNETS_CSV="$(get_cf_output RunsOnPublicSubnetIds)"
SECURITY_GROUP_ID="$(get_cf_output RunsOnSecurityGroupId)"

if [[ -z "${SUBNETS_CSV}" || "${SUBNETS_CSV}" == "None" ]]; then
  echo "failed to read RunsOnPublicSubnetIds from CloudFormation stack: ${STACK_NAME}" >&2
  exit 1
fi
if [[ -z "${SECURITY_GROUP_ID}" || "${SECURITY_GROUP_ID}" == "None" ]]; then
  echo "failed to read RunsOnSecurityGroupId from CloudFormation stack: ${STACK_NAME}" >&2
  exit 1
fi

IFS=',' read -r SUBNET_ID _rest <<<"${SUBNETS_CSV}"
if [[ -z "${SUBNET_ID}" ]]; then
  echo "could not select subnet from RunsOnPublicSubnetIds: ${SUBNETS_CSV}" >&2
  exit 1
fi

INSTANCE_ID=""
cleanup() {
  if [[ -n "${INSTANCE_ID}" ]]; then
    echo "terminating instance: ${INSTANCE_ID}" >&2
    awsj ec2 terminate-instances --instance-ids "${INSTANCE_ID}" >/dev/null || true
  fi
}
trap cleanup EXIT

echo "launching ${INSTANCE_TYPE} in ${REGION} (ami=${AMI_ID})" >&2
INSTANCE_ID="$(awsj ec2 run-instances \
  --image-id "${AMI_ID}" \
  --instance-type "${INSTANCE_TYPE}" \
  --subnet-id "${SUBNET_ID}" \
  --security-group-ids "${SECURITY_GROUP_ID}" \
  --iam-instance-profile "Name=${INSTANCE_PROFILE_NAME}" \
  --enclave-options 'Enabled=true' \
  --block-device-mappings '[
    {
      "DeviceName": "/dev/xvda",
      "Ebs": { "VolumeSize": 120, "VolumeType": "gp3", "DeleteOnTermination": true }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-crp-regtest-smoke},{Key=juno-intents,Value=crp-regtest-smoke}]' \
  --query 'Instances[0].InstanceId' \
  --output text)"

echo "instance: ${INSTANCE_ID}" >&2
echo "waiting for instance status ok..." >&2
awsj ec2 wait instance-status-ok --instance-ids "${INSTANCE_ID}"

echo "waiting for SSM online..." >&2
for _ in $(seq 1 120); do
  ping="$(awsj ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
    --query 'InstanceInformationList[0].PingStatus' \
    --output text 2>/dev/null || true)"
  if [[ "${ping}" == "Online" ]]; then
    break
  fi
  sleep 5
done
ping="$(awsj ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
  --query 'InstanceInformationList[0].PingStatus' \
  --output text 2>/dev/null || true)"
if [[ "${ping}" != "Online" ]]; then
  echo "SSM did not become Online (ping=${ping})" >&2
  exit 1
fi

send_ssm() {
  python3 - "$@" <<'PY'
import json
import os
import subprocess
import sys

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
timeout_seconds = os.environ.get("SSM_TIMEOUT_SECONDS", "").strip()
commands_json = sys.argv[1]
cmds = json.loads(commands_json)

payload = json.dumps({"commands": cmds})
args = [
    "aws",
    "--profile",
    "juno",
    "--region",
    region,
    "ssm",
    "send-command",
    "--document-name",
    "AWS-RunShellScript",
    "--targets",
    f"Key=InstanceIds,Values={instance_id}",
    "--parameters",
    payload,
    "--query",
    "Command.CommandId",
    "--output",
    "text",
]
if timeout_seconds:
    args += ["--timeout-seconds", timeout_seconds]
out = subprocess.check_output(args, text=True)
print(out.strip())
PY
}

wait_ssm() {
  local command_id="$1"
  local status="InProgress"
  local interval_s=5
  local max_wait_s="${SSM_TIMEOUT_SECONDS}"
  if [[ -z "${max_wait_s}" || "${max_wait_s}" -le 0 ]]; then
    max_wait_s=7200
  fi
  local max_iters="$(( (max_wait_s + interval_s - 1) / interval_s + 60 ))"
  for _ in $(seq 1 "${max_iters}"); do
    status="$(awsj ssm get-command-invocation \
      --command-id "${command_id}" \
      --instance-id "${INSTANCE_ID}" \
      --query 'Status' \
      --output text 2>/dev/null || true)"
    case "${status}" in
      Success|Failed|TimedOut|Cancelled)
        break
        ;;
      *)
        sleep "${interval_s}"
        ;;
    esac
  done
  echo "${status}"
}

export REGION INSTANCE_ID RELEASE_REPO RELEASE_TAG git_sha eif_sha256 KMS_KEY_ID KMS_VSOCK_PORT ENCLAVE_CID ENCLAVE_PORT ENCLAVE_MEM_MIB ENCLAVE_CPU_COUNT SSM_TIMEOUT_SECONDS
export OP1_SEALED_B64 OP2_SEALED_B64 OP1_EXPECTED OP2_EXPECTED DEPLOYMENT_NAME DEPLOYMENT_FILE DEPLOY_RPC_URL LAG MINE_BLOCKS CONFIG_SCAN_LIMIT CHECKPOINT_SCAN_LIMIT
export DEPLOYMENTS_JSON_B64
export PAYER_JSON_B64

CMDS="$(
  python3 - <<'PY'
import json, os
region=os.environ["REGION"]
release_repo=os.environ["RELEASE_REPO"]
release_tag=os.environ["RELEASE_TAG"]
git_sha=os.environ["git_sha"]
eif_sha256=os.environ["eif_sha256"]
kms_key_id=os.environ["KMS_KEY_ID"]
kms_vsock_port=os.environ["KMS_VSOCK_PORT"]
enclave_cid=os.environ["ENCLAVE_CID"]
enclave_port=os.environ["ENCLAVE_PORT"]
enclave_mem_mib=os.environ["ENCLAVE_MEM_MIB"]
enclave_cpu_count=os.environ["ENCLAVE_CPU_COUNT"]
op1_b64=os.environ["OP1_SEALED_B64"]
op2_b64=os.environ["OP2_SEALED_B64"]
op1_expected=os.environ.get("OP1_EXPECTED","").strip()
op2_expected=os.environ.get("OP2_EXPECTED","").strip()
deployment_name=os.environ["DEPLOYMENT_NAME"]
deployments_b64=os.environ["DEPLOYMENTS_JSON_B64"]
rpc_url=os.environ["DEPLOY_RPC_URL"]
lag=os.environ["LAG"]
mine_blocks=os.environ["MINE_BLOCKS"]
cfg_scan=os.environ["CONFIG_SCAN_LIMIT"]
chk_scan=os.environ["CHECKPOINT_SCAN_LIMIT"]
payer_b64=os.environ["PAYER_JSON_B64"]

cmds=[
  "set -euo pipefail",
  f"export DEPLOY_RPC_URL='{rpc_url}'",
  f"export DEPLOYMENTS_JSON_B64='{deployments_b64}'",
  f"export OP1_SEALED_B64='{op1_b64}'",
  f"export OP2_SEALED_B64='{op2_b64}'",
  f"export PAYER_JSON_B64='{payer_b64}'",
  "sudo dnf install -y git docker python3 curl-minimal >/tmp/dnf-install.log 2>&1 || { tail -n 200 /tmp/dnf-install.log >&2; exit 1; }",
  "sudo systemctl enable --now docker",
  "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel >/tmp/dnf-nitro.log 2>&1 || sudo dnf install -y aws-nitro-enclaves-cli >/tmp/dnf-nitro.log 2>&1 || { tail -n 200 /tmp/dnf-nitro.log >&2; exit 1; }",
  "nitro-cli --version || true",
  "sudo mkdir -p /etc/nitro_enclaves",
  f"cat <<'YAML' | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null\n---\nmemory_mib: {enclave_mem_mib}\ncpu_count: {enclave_cpu_count}\nYAML",
  "sudo systemctl enable --now nitro-enclaves-allocator || { systemctl status --no-pager nitro-enclaves-allocator || true; journalctl -xeu nitro-enclaves-allocator --no-pager | tail -n 200 || true; exit 1; }",
  "mkdir -p /tmp/juno-eif",
  f"BASE_URL=\"https://github.com/{release_repo}/releases/download/{release_tag}\"",
  "curl -fsSL \"${BASE_URL}/operator.eif\" -o /tmp/juno-eif/operator.eif",
  f"EXPECTED_EIF_SHA256=\"{eif_sha256}\"",
  r"""ACTUAL_EIF_SHA256="$(sha256sum /tmp/juno-eif/operator.eif | awk '{print $1}')" """,
  "if [[ \"${ACTUAL_EIF_SHA256}\" != \"${EXPECTED_EIF_SHA256}\" ]]; then echo \"operator.eif sha256 mismatch\" >&2; exit 1; fi",
  "cd /tmp",
  f"rm -rf juno-intents && git clone https://github.com/{release_repo}.git juno-intents >/dev/null",
  "cd juno-intents",
  f"git checkout {git_sha} >/dev/null",
  "python3 - <<'PYDEP'\nimport base64,os\nraw=base64.b64decode(os.environ['DEPLOYMENTS_JSON_B64'].encode('ascii'))\nopen('deployments.json','wb').write(raw)\nPYDEP",
  "mkdir -p tmp/enclave tmp/keys",
  "cp /tmp/juno-eif/operator.eif tmp/enclave/operator.eif",
  "python3 - <<'PYK1'\nimport base64,os\nb=base64.b64decode(os.environ['OP1_SEALED_B64'].encode('ascii'))\nopen('tmp/keys/op1.sealed.json','wb').write(b)\nPYK1",
  "python3 - <<'PYK2'\nimport base64,os\nb=base64.b64decode(os.environ['OP2_SEALED_B64'].encode('ascii'))\nopen('tmp/keys/op2.sealed.json','wb').write(b)\nPYK2",
  "VSOCK_PROXY=\"$(command -v vsock-proxy || command -v nitro-enclaves-vsock-proxy || true)\"",
  "if [[ -z \"${VSOCK_PROXY}\" ]]; then echo \"missing vsock-proxy\" >&2; exit 1; fi",
  f"sudo nohup \"${{VSOCK_PROXY}}\" {kms_vsock_port} kms.{region}.amazonaws.com 443 >/var/log/vsock-proxy.log 2>&1 &",
  "sleep 1",
  f"sudo nitro-cli run-enclave --eif-path tmp/enclave/operator.eif --cpu-count {enclave_cpu_count} --memory {enclave_mem_mib} --enclave-cid {enclave_cid}",
  "sleep 2",
  "BUILDER_IMAGE=\"$(awk '/^FROM --platform=linux\\/amd64 golang:/{print $3}' enclave/operator/Dockerfile | head -n 1)\"",
  "docker pull -q \"${BUILDER_IMAGE}\" >/dev/null 2>&1 || true",
  "mkdir -p tmp/bin",
  "docker run --rm -v \"$PWD\":/src -w /src \"$BUILDER_IMAGE\" go build -trimpath -buildvcs=false -mod=readonly -ldflags \"-s -w -buildid=\" -o ./tmp/bin/nitro-operator ./cmd/nitro-operator >/dev/null",
  "docker run --rm -v \"$PWD\":/src -w /src \"$BUILDER_IMAGE\" go build -trimpath -buildvcs=false -mod=readonly -ldflags \"-s -w -buildid=\" -o ./tmp/bin/crp-operator ./cmd/crp-operator >/dev/null",
  "python3 - <<'PYPAYER'\nimport base64,os\nraw=base64.b64decode(os.environ['PAYER_JSON_B64'].encode('ascii'))\nos.makedirs('tmp', exist_ok=True)\nopen('tmp/payer.json','wb').write(raw)\nos.chmod('tmp/payer.json', 0o600)\nprint('payer_keypair=tmp/payer.json')\nPYPAYER",
  "scripts/junocash/regtest/up.sh",
  f"scripts/junocash/regtest/cli.sh generate {mine_blocks} >/dev/null",
  "TIP=\"$(scripts/junocash/regtest/cli.sh getblockcount)\"",
  f"LAG=\"{lag}\"",
  "START=\"$((TIP - LAG))\"",
  "echo \"regtest_tip=${TIP} start_height=${START} lag=${LAG}\"",
  f"export SOLANA_RPC_URL='{rpc_url}'",
  "export RUST_LOG=info",
  f"./tmp/bin/nitro-operator init-key --enclave-cid {enclave_cid} --enclave-port {enclave_port} --region {region} --kms-key-id '{kms_key_id}' --kms-vsock-port {kms_vsock_port} --sealed-key-file ./tmp/keys/op1.sealed.json >/tmp/op1.init.log",
  "OP1_PUB=\"$(grep -E '^operator_pubkey_base58=' /tmp/op1.init.log | sed -nE 's/^operator_pubkey_base58=(.+)$/\\1/p' | head -n 1)\"",
  "echo \"operator1_pubkey=${OP1_PUB}\"",
  f"if [[ -n '{op1_expected}' && \"${{OP1_PUB}}\" != '{op1_expected}' ]]; then echo \"operator1 pubkey mismatch (got=${{OP1_PUB}} expected={op1_expected})\" >&2; exit 1; fi",
  f"./tmp/bin/crp-operator run --deployment '{deployment_name}' --start-height \"${{START}}\" --lag \"${{LAG}}\" --poll-interval 1s --payer-keypair ./tmp/payer.json --submit-operator-enclave-cid {enclave_cid} --submit-operator-enclave-port {enclave_port} --junocash-cli scripts/junocash/regtest/cli.sh --cu-limit-submit 200000 --priority-level Medium --once --submit-only",
  f"./tmp/bin/nitro-operator init-key --enclave-cid {enclave_cid} --enclave-port {enclave_port} --region {region} --kms-key-id '{kms_key_id}' --kms-vsock-port {kms_vsock_port} --sealed-key-file ./tmp/keys/op2.sealed.json >/tmp/op2.init.log",
  "OP2_PUB=\"$(grep -E '^operator_pubkey_base58=' /tmp/op2.init.log | sed -nE 's/^operator_pubkey_base58=(.+)$/\\1/p' | head -n 1)\"",
  "echo \"operator2_pubkey=${OP2_PUB}\"",
  f"if [[ -n '{op2_expected}' && \"${{OP2_PUB}}\" != '{op2_expected}' ]]; then echo \"operator2 pubkey mismatch (got=${{OP2_PUB}} expected={op2_expected})\" >&2; exit 1; fi",
  f"./tmp/bin/crp-operator run --deployment '{deployment_name}' --start-height \"${{START}}\" --lag \"${{LAG}}\" --poll-interval 1s --payer-keypair ./tmp/payer.json --submit-operator-enclave-cid {enclave_cid} --submit-operator-enclave-port {enclave_port} --junocash-cli scripts/junocash/regtest/cli.sh --cu-limit-submit 200000 --priority-level Medium --once --submit-only",
  f"./tmp/bin/crp-operator finalize-pending --deployment '{deployment_name}' --payer-keypair ./tmp/payer.json --config-scan-limit {cfg_scan} --scan-limit {chk_scan} --max-checkpoints 1 --cu-limit 250000 --priority-level Medium",
]
print(json.dumps(cmds))
PY
)"

CMD_ID="$(send_ssm "${CMDS}")"
echo "ssm command id: ${CMD_ID}" >&2
echo "waiting for command to finish..." >&2
status="$(wait_ssm "${CMD_ID}")"
echo "ssm status: ${status}" >&2

stdout="$(awsj ssm get-command-invocation --command-id "${CMD_ID}" --instance-id "${INSTANCE_ID}" --query 'StandardOutputContent' --output text 2>/dev/null || true)"
stderr="$(awsj ssm get-command-invocation --command-id "${CMD_ID}" --instance-id "${INSTANCE_ID}" --query 'StandardErrorContent' --output text 2>/dev/null || true)"

if [[ -n "${stdout}" && "${stdout}" != "None" ]]; then
  echo "${stdout}"
fi
if [[ -n "${stderr}" && "${stderr}" != "None" ]]; then
  echo "${stderr}" >&2
fi

if [[ "${status}" != "Success" ]]; then
  exit 1
fi
