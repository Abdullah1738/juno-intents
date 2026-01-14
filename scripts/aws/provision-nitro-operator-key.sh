#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Pin to a concrete AL2023 AMI (us-east-1) for repeatable tooling.
AMI_ID="${JUNO_NITRO_PROVISION_AMI_ID:-ami-07ff62358b87c7116}"
INSTANCE_TYPE="${JUNO_NITRO_PROVISION_INSTANCE_TYPE:-c6i.xlarge}"

RELEASE_REPO="${JUNO_NITRO_EIF_RELEASE_REPO:-Abdullah1738/juno-intents}"
RELEASE_TAG="${JUNO_NITRO_EIF_RELEASE_TAG:-}"

KMS_KEY_ID="${JUNO_NITRO_KMS_KEY_ID:-alias/juno-intents-nitro-operator}"
KMS_VSOCK_PORT="${JUNO_NITRO_KMS_VSOCK_PORT:-8000}"
ENCLAVE_CID="${JUNO_NITRO_ENCLAVE_CID:-16}"
ENCLAVE_PORT="${JUNO_NITRO_ENCLAVE_PORT:-5000}"
ENCLAVE_MEM_MIB="${JUNO_NITRO_ENCLAVE_MEM_MIB:-1024}"
ENCLAVE_CPU_COUNT="${JUNO_NITRO_ENCLAVE_CPU_COUNT:-2}"

INSTANCE_PROFILE_NAME="${JUNO_NITRO_INSTANCE_PROFILE_NAME:-}"

OUT_DIR="${JUNO_NITRO_SEALED_KEY_OUT_DIR:-${ROOT}/tmp/nitro-operator-keys}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/provision-nitro-operator-key.sh --eif-release-tag <tag> [--eif-release-repo <owner/repo>]

Environment:
  JUNO_AWS_REGION                  (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME          (default: runs-on)
  JUNO_NITRO_PROVISION_AMI_ID      (default: al2023 us-east-1 pinned)
  JUNO_NITRO_PROVISION_INSTANCE_TYPE (default: c6i.xlarge)
  JUNO_NITRO_INSTANCE_PROFILE_NAME (default: terraform output instance_profile_name, else juno-intents-nitro-operator)

  JUNO_NITRO_EIF_RELEASE_REPO      (default: Abdullah1738/juno-intents)
  JUNO_NITRO_EIF_RELEASE_TAG       (required)

  JUNO_NITRO_KMS_KEY_ID            (default: alias/juno-intents-nitro-operator)
  JUNO_NITRO_KMS_VSOCK_PORT        (default: 8000)
  JUNO_NITRO_ENCLAVE_CID           (default: 16)
  JUNO_NITRO_ENCLAVE_PORT          (default: 5000)
  JUNO_NITRO_ENCLAVE_MEM_MIB       (default: 1024)
  JUNO_NITRO_ENCLAVE_CPU_COUNT     (default: 2)

  JUNO_NITRO_SEALED_KEY_OUT_DIR    (default: tmp/nitro-operator-keys)

Notes:
  - Fetches operator.meta.json from the GitHub release, pins PCR0 into terraform (allowed_pcr0), then provisions a fresh sealed signing key inside Nitro.
  - The instance is ALWAYS terminated on exit (success/failure).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --eif-release-tag)
      RELEASE_TAG="${2:-}"
      shift 2
      ;;
    --eif-release-repo)
      RELEASE_REPO="${2:-}"
      shift 2
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${RELEASE_TAG}" ]]; then
  echo "--eif-release-tag is required" >&2
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
INSTANCE_ID=""
cleanup() {
  if [[ -n "${INSTANCE_ID}" ]]; then
    echo "terminating instance: ${INSTANCE_ID}" >&2
    awsj ec2 terminate-instances --instance-ids "${INSTANCE_ID}" >/dev/null || true
  fi
  rm -f "${META_PATH}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "fetching operator.meta.json from GitHub release..." >&2
python3 - "${RELEASE_REPO}" "${RELEASE_TAG}" "${META_PATH}" <<'PY'
import sys
import urllib.request

repo = sys.argv[1]
tag = sys.argv[2]
path = sys.argv[3]
url = f"https://github.com/{repo}/releases/download/{tag}/operator.meta.json"

try:
  with urllib.request.urlopen(url, timeout=30) as r:
    data = r.read()
except Exception as e:
  raise SystemExit(f"failed to download operator.meta.json: {e}")

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
      "Ebs": { "VolumeSize": 80, "VolumeType": "gp3", "DeleteOnTermination": true }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-nitro-provision},{Key=juno-intents,Value=nitro-provision}]' \
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
commands_json = sys.argv[1]
cmds = json.loads(commands_json)

payload = json.dumps({"commands": cmds})
out = subprocess.check_output(
    [
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
    ],
    text=True,
)
print(out.strip())
PY
}

wait_ssm() {
  local command_id="$1"
  local status="InProgress"
  for _ in $(seq 1 360); do
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
        sleep 5
        ;;
    esac
  done
  echo "${status}"
}

export REGION INSTANCE_ID RELEASE_REPO RELEASE_TAG git_sha eif_sha256 KMS_KEY_ID KMS_VSOCK_PORT ENCLAVE_CID ENCLAVE_PORT ENCLAVE_MEM_MIB ENCLAVE_CPU_COUNT

CMDS="$(
  python3 - <<'PY'
import json,os
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

cmds=[
  "set -euo pipefail",
  "sudo dnf install -y git docker python3 >/tmp/dnf-install.log 2>&1 || { tail -n 200 /tmp/dnf-install.log >&2; exit 1; }",
  "command -v curl >/dev/null || (sudo dnf install -y curl-minimal >/tmp/dnf-curl.log 2>&1 || { tail -n 200 /tmp/dnf-curl.log >&2; exit 1; })",
  "sudo systemctl enable --now docker",
  "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel >/tmp/dnf-nitro.log 2>&1 || sudo dnf install -y aws-nitro-enclaves-cli >/tmp/dnf-nitro.log 2>&1 || { tail -n 200 /tmp/dnf-nitro.log >&2; exit 1; }",
  "nitro-cli --version || true",
  "sudo mkdir -p /etc/nitro_enclaves",
  f"cat <<'YAML' | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null\n---\nmemory_mib: {enclave_mem_mib}\ncpu_count: {enclave_cpu_count}\nYAML",
  "sudo systemctl enable --now nitro-enclaves-allocator || { echo \"allocator_failed\" >&2; ls -la /dev/nitro_enclaves /dev/nsm || true; cat /etc/nitro_enclaves/allocator.yaml || true; systemctl status --no-pager nitro-enclaves-allocator || true; journalctl -xeu nitro-enclaves-allocator --no-pager | tail -n 200 || true; exit 1; }",
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
  "mkdir -p tmp/enclave",
  "cp /tmp/juno-eif/operator.eif tmp/enclave/operator.eif",
  "VSOCK_PROXY=\"$(command -v vsock-proxy || command -v nitro-enclaves-vsock-proxy || true)\"",
  "if [[ -z \"${VSOCK_PROXY}\" ]]; then echo \"missing vsock-proxy\" >&2; exit 1; fi",
  f"sudo nohup \"${{VSOCK_PROXY}}\" {kms_vsock_port} kms.{region}.amazonaws.com 443 >/var/log/vsock-proxy.log 2>&1 &",
  "sleep 1",
  f"sudo nitro-cli run-enclave --eif-path tmp/enclave/operator.eif --cpu-count {enclave_cpu_count} --memory {enclave_mem_mib} --enclave-cid {enclave_cid}",
  "sleep 2",
  "BUILDER_IMAGE=\"$(awk '/^FROM --platform=linux\\/amd64 golang:/{print $3}' enclave/operator/Dockerfile | head -n 1)\"",
  "docker pull -q \"${BUILDER_IMAGE}\" >/dev/null 2>&1 || true",
  "mkdir -p tmp",
  "docker run --rm -v \"$PWD\":/src -w /src \"$BUILDER_IMAGE\" go build -trimpath -buildvcs=false -mod=readonly -ldflags \"-s -w -buildid=\" -o ./tmp/nitro-operator ./cmd/nitro-operator >./tmp/nitro-operator.build.log 2>&1 || { tail -n 200 ./tmp/nitro-operator.build.log >&2; exit 1; }",
  f"./tmp/nitro-operator init-key --enclave-cid {enclave_cid} --enclave-port {enclave_port} --region {region} --kms-key-id '{kms_key_id}' --kms-vsock-port {kms_vsock_port} --sealed-key-file ./tmp/nitro-operator.sealed.json || {{ echo 'init-key failed' >&2; sudo tail -n 200 /var/log/vsock-proxy.log || true; exit 1; }}",
  r"""SEALED_B64="$(python3 - <<'PYB64'
import base64
with open("./tmp/nitro-operator.sealed.json","rb") as f:
  print(base64.b64encode(f.read()).decode("ascii"))
PYB64
)" """,
  "echo \"sealed_key_b64=${SEALED_B64}\"",
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

if [[ "${status}" != "Success" ]]; then
  printf '%s\n' "${stdout}" >&2
  printf '%s\n' "${stderr}" >&2
  exit 1
fi

joined="$(printf '%s\n%s\n' "${stdout}" "${stderr}" | tr -d '\r')"

operator_pubkey_base58="$(printf '%s\n' "${joined}" | sed -nE 's/^operator_pubkey_base58=(.+)$/\1/p' | head -n 1)"
operator_pubkey_hex="$(printf '%s\n' "${joined}" | sed -nE 's/^operator_pubkey_hex=(.+)$/\1/p' | head -n 1)"
sealed_key_b64="$(printf '%s\n' "${joined}" | sed -nE 's/^sealed_key_b64=(.+)$/\1/p' | tail -n 1)"

if [[ -z "${operator_pubkey_base58}" || -z "${sealed_key_b64}" ]]; then
  echo "failed to parse operator_pubkey_base58/sealed_key_b64 from SSM output" >&2
  printf '%s\n' "${stdout}" >&2
  printf '%s\n' "${stderr}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
OUT_FILE="${OUT_DIR}/${operator_pubkey_base58}.sealed.json"
python3 - "${sealed_key_b64}" "${OUT_FILE}" <<'PY'
import base64
import os
import sys

b64 = sys.argv[1].strip()
path = sys.argv[2]
raw = base64.b64decode(b64.encode("ascii"))

os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "wb") as f:
  f.write(raw)
try:
  os.chmod(path, 0o600)
except Exception:
  pass
PY

echo "operator_pubkey_base58=${operator_pubkey_base58}"
echo "operator_pubkey_hex=${operator_pubkey_hex}"
echo "sealed_key_file_local=${OUT_FILE}"
echo "eif_release_repo=${RELEASE_REPO}"
echo "eif_release_tag=${RELEASE_TAG}"
echo "git_sha=${git_sha}"
echo "pcr0=${pcr0}"
echo "eif_sha256=${eif_sha256}"
