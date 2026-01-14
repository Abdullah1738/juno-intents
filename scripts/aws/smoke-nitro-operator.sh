#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Pin to a concrete AL2023 AMI (us-east-1) for repeatable tooling.
AMI_ID="${JUNO_NITRO_SMOKE_AMI_ID:-ami-07ff62358b87c7116}"
INSTANCE_TYPE="${JUNO_NITRO_SMOKE_INSTANCE_TYPE:-c6i.xlarge}"

REPO="${JUNO_EIF_GIT_REPO:-Abdullah1738/juno-intents}"
REF="${JUNO_EIF_GIT_REF:-}"

EIF_SOURCE="${JUNO_NITRO_EIF_SOURCE:-build}" # build | release
EIF_RELEASE_TAG="${JUNO_NITRO_EIF_RELEASE_TAG:-}"
EIF_RELEASE_REPO="${JUNO_NITRO_EIF_RELEASE_REPO:-${REPO}}"

KMS_KEY_ID="${JUNO_NITRO_KMS_KEY_ID:-alias/juno-intents-nitro-operator}"
KMS_VSOCK_PORT="${JUNO_NITRO_KMS_VSOCK_PORT:-8000}"
ENCLAVE_CID="${JUNO_NITRO_ENCLAVE_CID:-16}"
ENCLAVE_PORT="${JUNO_NITRO_ENCLAVE_PORT:-5000}"
ENCLAVE_MEM_MIB="${JUNO_NITRO_ENCLAVE_MEM_MIB:-1024}"
ENCLAVE_CPU_COUNT="${JUNO_NITRO_ENCLAVE_CPU_COUNT:-2}"

INSTANCE_PROFILE_NAME="${JUNO_NITRO_INSTANCE_PROFILE_NAME:-}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/smoke-nitro-operator.sh [--ref <git-ref>]

Environment:
  JUNO_AWS_REGION                  (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME          (default: runs-on)
  JUNO_NITRO_SMOKE_AMI_ID          (default: al2023 us-east-1 pinned)
  JUNO_NITRO_SMOKE_INSTANCE_TYPE   (default: c6i.xlarge)
  JUNO_NITRO_INSTANCE_PROFILE_NAME (default: terraform output instance_profile_name, else juno-intents-nitro-operator)
  JUNO_EIF_GIT_REPO                (default: Abdullah1738/juno-intents)
  JUNO_EIF_GIT_REF                 (default: current HEAD if available, else main)

  JUNO_NITRO_EIF_SOURCE            (default: build; build|release)
  JUNO_NITRO_EIF_RELEASE_TAG       (required if source=release; GitHub release tag)
  JUNO_NITRO_EIF_RELEASE_REPO      (default: JUNO_EIF_GIT_REPO; owner/repo for release downloads)

  JUNO_NITRO_KMS_KEY_ID            (default: alias/juno-intents-nitro-operator)
  JUNO_NITRO_KMS_VSOCK_PORT        (default: 8000)
  JUNO_NITRO_ENCLAVE_CID           (default: 16)
  JUNO_NITRO_ENCLAVE_PORT          (default: 5000)
  JUNO_NITRO_ENCLAVE_MEM_MIB       (default: 1024)
  JUNO_NITRO_ENCLAVE_CPU_COUNT     (default: 2)

Notes:
  - All AWS calls use: --profile juno
  - The instance is ALWAYS terminated on exit (success/failure).
  - This is a KMS+attestation smoke test (init_signing_key) only.
  - In release mode, the host downloads operator.eif/operator.meta.json from GitHub Releases and pins PCR0 from the release metadata.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --eif-source)
      EIF_SOURCE="${2:-}"
      shift 2
      ;;
    --eif-release-tag)
      EIF_RELEASE_TAG="${2:-}"
      shift 2
      ;;
    --eif-release-repo)
      EIF_RELEASE_REPO="${2:-}"
      shift 2
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

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

if [[ -z "${REF}" ]]; then
  if git -C "${ROOT}" rev-parse HEAD >/dev/null 2>&1; then
    REF="$(git -C "${ROOT}" rev-parse HEAD)"
  else
    REF="main"
  fi
fi

if [[ "${EIF_SOURCE}" != "build" && "${EIF_SOURCE}" != "release" ]]; then
  echo "--eif-source must be 'build' or 'release' (got: ${EIF_SOURCE})" >&2
  exit 2
fi
if [[ "${EIF_SOURCE}" == "release" && -z "${EIF_RELEASE_TAG}" ]]; then
  echo "--eif-release-tag is required when --eif-source=release" >&2
  exit 2
fi

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
      "Ebs": { "VolumeSize": 80, "VolumeType": "gp3", "DeleteOnTermination": true }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-nitro-smoke},{Key=juno-intents,Value=nitro-smoke}]' \
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

echo "running smoke test via SSM (phase 1: build EIF + capture PCR0)..." >&2
export REGION INSTANCE_ID REPO REF EIF_SOURCE EIF_RELEASE_TAG EIF_RELEASE_REPO KMS_KEY_ID KMS_VSOCK_PORT ENCLAVE_CID ENCLAVE_PORT ENCLAVE_MEM_MIB ENCLAVE_CPU_COUNT

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

PHASE1_CMDS="$(
  python3 - <<'PY'
import json,os
enclave_mem_mib=os.environ["ENCLAVE_MEM_MIB"]
enclave_cpu_count=os.environ["ENCLAVE_CPU_COUNT"]
eif_source=os.environ.get("EIF_SOURCE","build")
repo=os.environ["REPO"]
ref=os.environ["REF"]
release_repo=os.environ.get("EIF_RELEASE_REPO","")
release_tag=os.environ.get("EIF_RELEASE_TAG","")

cmds=[
  "set -euo pipefail",
  "sudo dnf install -y git docker python3",
  "command -v curl >/dev/null || sudo dnf install -y curl-minimal",
  "sudo systemctl enable --now docker",
  "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel || sudo dnf install -y aws-nitro-enclaves-cli",
  "nitro-cli --version || true",
  "sudo mkdir -p /etc/nitro_enclaves",
  f"cat <<'YAML' | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null\n---\nmemory_mib: {enclave_mem_mib}\ncpu_count: {enclave_cpu_count}\nYAML",
  "sudo systemctl enable --now nitro-enclaves-allocator || { echo \"allocator_failed\" >&2; ls -la /dev/nitro_enclaves /dev/nsm || true; cat /etc/nitro_enclaves/allocator.yaml || true; systemctl status --no-pager nitro-enclaves-allocator || true; journalctl -xeu nitro-enclaves-allocator --no-pager | tail -n 200 || true; exit 1; }",
]

if eif_source == "build":
  cmds += [
    f"rm -rf juno-intents && git clone https://github.com/{repo}.git juno-intents",
    "cd juno-intents",
    f"git checkout {ref}",
    "scripts/enclave/build-eif.sh",
  ]
elif eif_source == "release":
  if not release_repo or not release_tag:
    raise SystemExit("release mode requires EIF_RELEASE_REPO and EIF_RELEASE_TAG")
  cmds += [
    "mkdir -p /tmp/juno-eif",
    f"BASE_URL=\"https://github.com/{release_repo}/releases/download/{release_tag}\"",
    "echo \"eif_base_url=${BASE_URL}\"",
    "curl -fsSL \"${BASE_URL}/operator.meta.json\" -o /tmp/juno-eif/operator.meta.json",
    "curl -fsSL \"${BASE_URL}/operator.eif\" -o /tmp/juno-eif/operator.eif",
    r"""python3 - <<'PYMETA'
import hashlib
import json

with open("/tmp/juno-eif/operator.meta.json","r",encoding="utf-8") as f:
  meta=json.load(f)

expected=(meta.get("eif_sha256") or "").strip().lower()
if len(expected) != 64:
  raise SystemExit("missing/invalid eif_sha256 in operator.meta.json")

h=hashlib.sha256()
with open("/tmp/juno-eif/operator.eif","rb") as f:
  for chunk in iter(lambda: f.read(1024*1024), b""):
    h.update(chunk)
got=h.hexdigest()
if got != expected:
  raise SystemExit(f"operator.eif sha256 mismatch (expected={expected} got={got})")

pcr0=(meta.get("pcr0") or "").strip().lower()
if len(pcr0) != 96:
  raise SystemExit("missing/invalid pcr0 in operator.meta.json")

print(f"pcr0={pcr0}")
print(f"eif_sha256={expected}")
print(f"git_sha={(meta.get('git_sha') or '').strip()}")
PYMETA""",
  ]
else:
  raise SystemExit(f"invalid eif_source: {eif_source}")
print(json.dumps(cmds))
PY
)"

PHASE1_ID="$(send_ssm "${PHASE1_CMDS}")"
echo "ssm phase1 command id: ${PHASE1_ID}" >&2
echo "waiting for phase1 to finish..." >&2
phase1_status="$(wait_ssm "${PHASE1_ID}")"
echo "ssm phase1 status: ${phase1_status}" >&2
phase1_stdout="$(awsj ssm get-command-invocation \
  --command-id "${PHASE1_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query 'StandardOutputContent' \
  --output text 2>/dev/null || true)"
phase1_stderr="$(awsj ssm get-command-invocation \
  --command-id "${PHASE1_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query 'StandardErrorContent' \
  --output text 2>/dev/null || true)"
printf '%s\n' "${phase1_stdout}" >&2
printf '%s\n' "${phase1_stderr}" >&2
if [[ "${phase1_status}" != "Success" ]]; then
  exit 1
fi

pcr0="$(
  printf '%s\n%s\n' "${phase1_stdout}" "${phase1_stderr}" \
    | tr -d '\r' \
    | sed -nE 's/^pcr0=([0-9a-fA-F]{96})$/\1/p' \
    | head -n 1 \
    | tr 'A-F' 'a-f'
)"
if [[ -z "${pcr0}" ]]; then
  echo "failed to extract pcr0 from phase1 output" >&2
  exit 1
fi
echo "pcr0=${pcr0}" >&2

echo "applying terraform allowed_pcr0..." >&2
terraform -chdir="${ROOT}/infra/terraform/nitro-operator" apply -auto-approve -var "allowed_pcr0=[\"${pcr0}\"]" >/dev/null
sleep 5

echo "running smoke test via SSM (phase 2: run enclave + init key)..." >&2
PHASE2_CMDS="$(
  python3 - <<'PY'
import json,os
region=os.environ["REGION"]
kms_key_id=os.environ["KMS_KEY_ID"]
kms_vsock_port=os.environ["KMS_VSOCK_PORT"]
enclave_cid=os.environ["ENCLAVE_CID"]
enclave_port=os.environ["ENCLAVE_PORT"]
enclave_mem_mib=os.environ["ENCLAVE_MEM_MIB"]
enclave_cpu_count=os.environ["ENCLAVE_CPU_COUNT"]
eif_source=os.environ.get("EIF_SOURCE","build")
repo=os.environ["REPO"]
ref=os.environ["REF"]

cmds=["set -euo pipefail"]

if eif_source == "build":
  cmds += [
    "cd juno-intents",
  ]
elif eif_source == "release":
  cmds += [
    "cd /tmp",
    f"rm -rf juno-intents && git clone https://github.com/{repo}.git juno-intents",
    "cd juno-intents",
    r"""GIT_SHA="$(python3 - <<'PYMETA'
import json
with open("/tmp/juno-eif/operator.meta.json","r",encoding="utf-8") as f:
  meta=json.load(f)
print((meta.get("git_sha") or "").strip())
PYMETA
)" """,
    "if [[ -n \"${GIT_SHA}\" ]]; then git checkout \"${GIT_SHA}\"; else git checkout " + ref + "; fi",
    "mkdir -p tmp/enclave",
    "cp /tmp/juno-eif/operator.eif tmp/enclave/operator.eif",
    "cp /tmp/juno-eif/operator.meta.json tmp/enclave/operator.meta.json",
  ]
else:
  raise SystemExit(f"invalid eif_source: {eif_source}")

cmds += [
  "VSOCK_PROXY=\"$(command -v vsock-proxy || command -v nitro-enclaves-vsock-proxy || true)\"",
  "if [[ -z \"${VSOCK_PROXY}\" ]]; then echo \"missing vsock-proxy\" >&2; exit 1; fi",
  "echo \"vsock-proxy=${VSOCK_PROXY}\"",
  f"sudo nohup \"${{VSOCK_PROXY}}\" {kms_vsock_port} kms.{region}.amazonaws.com 443 >/var/log/vsock-proxy.log 2>&1 &",
  "sleep 1",
  f"sudo nitro-cli run-enclave --eif-path tmp/enclave/operator.eif --cpu-count {enclave_cpu_count} --memory {enclave_mem_mib} --enclave-cid {enclave_cid}",
  "sleep 2",
  "BUILDER_IMAGE=\"$(awk '/^FROM --platform=linux\\/amd64 golang:/{print $3}' enclave/operator/Dockerfile | head -n 1)\"",
  "echo \"builder_image=${BUILDER_IMAGE}\"",
  "mkdir -p tmp",
  "docker run --rm -v \"$PWD\":/src -w /src \"$BUILDER_IMAGE\" go build -trimpath -buildvcs=false -mod=readonly -ldflags \"-s -w -buildid=\" -o ./tmp/nitro-operator ./cmd/nitro-operator",
  f"./tmp/nitro-operator init-key --enclave-cid {enclave_cid} --enclave-port {enclave_port} --region {region} --kms-key-id '{kms_key_id}' --kms-vsock-port {kms_vsock_port} --sealed-key-file ./tmp/nitro-operator.sealed.json || {{ echo 'init-key failed' >&2; sudo tail -n 200 /var/log/vsock-proxy.log || true; exit 1; }}",
  "ls -la ./tmp/nitro-operator.sealed.json",
]
print(json.dumps(cmds))
PY
)"

PHASE2_ID="$(send_ssm "${PHASE2_CMDS}")"
echo "ssm phase2 command id: ${PHASE2_ID}" >&2
echo "waiting for phase2 to finish..." >&2
phase2_status="$(wait_ssm "${PHASE2_ID}")"
echo "ssm phase2 status: ${phase2_status}" >&2
phase2_stdout="$(awsj ssm get-command-invocation \
  --command-id "${PHASE2_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query 'StandardOutputContent' \
  --output text 2>/dev/null || true)"
phase2_stderr="$(awsj ssm get-command-invocation \
  --command-id "${PHASE2_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query 'StandardErrorContent' \
  --output text 2>/dev/null || true)"
printf '%s\n' "${phase2_stdout}" >&2
printf '%s\n' "${phase2_stderr}" >&2
if [[ "${phase2_status}" != "Success" ]]; then
  exit 1
fi

for key in operator_pubkey_base58 operator_pubkey_hex sealed_key_file; do
  val="$(
    printf '%s\n%s\n' "${phase2_stdout}" "${phase2_stderr}" \
      | tr -d '\r' \
      | sed -nE "s/^${key}=(.+)$/\\1/p" \
      | head -n 1
  )"
  if [[ -n "${val}" ]]; then
    echo "${key}=${val}"
  fi
done
