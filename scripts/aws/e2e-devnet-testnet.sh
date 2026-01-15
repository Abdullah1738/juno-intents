#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

AMI_ID="${JUNO_E2E_AMI_ID:-ami-06d69846519cd5d6f}"
INSTANCE_TYPE="${JUNO_E2E_INSTANCE_TYPE:-g5.4xlarge}"

RUST_TOOLCHAIN="${JUNO_RUST_TOOLCHAIN:-1.91.1}"
RISC0_RUST_TOOLCHAIN="${JUNO_RISC0_RUST_TOOLCHAIN:-1.91.1}"
RZUP_VERSION="${JUNO_RZUP_VERSION:-0.5.1}"
RISC0_GROTH16_VERSION="${JUNO_RISC0_GROTH16_VERSION:-0.1.0}"
GO_VERSION="${JUNO_GO_VERSION:-1.22.6}"

REF=""
DEPLOYMENT_NAME=""

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/e2e-devnet-testnet.sh --deployment <name> [--ref <git-ref>]

Environment:
  JUNO_AWS_REGION            (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME    (default: runs-on)
  JUNO_E2E_AMI_ID            (default: runs-on GPU AMI)
  JUNO_E2E_INSTANCE_TYPE     (default: g5.4xlarge)

Notes:
  - Uses AWS SSM on a short-lived GPU instance (uses --profile juno).
  - Runs scripts/e2e/devnet-testnet.sh inside the instance.
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
    --ref)
      REF="${2:-}"; shift 2 ;;
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

if [[ -z "${REF}" ]]; then
  REF="$(git -C "${ROOT}" rev-parse HEAD)"
fi
GIT_SHA="$(git -C "${ROOT}" rev-parse "${REF}^{commit}")"

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

SUBNETS_CSV="$(get_cf_output RunsOnPublicSubnetIds)"
SECURITY_GROUP_ID="$(get_cf_output RunsOnSecurityGroupId)"
ROLE_NAME="$(get_cf_output RunsOnInstanceRoleName)"

if [[ -z "${SUBNETS_CSV}" || "${SUBNETS_CSV}" == "None" ]]; then
  echo "failed to read RunsOnPublicSubnetIds from CloudFormation stack: ${STACK_NAME}" >&2
  exit 1
fi
if [[ -z "${SECURITY_GROUP_ID}" || "${SECURITY_GROUP_ID}" == "None" ]]; then
  echo "failed to read RunsOnSecurityGroupId from CloudFormation stack: ${STACK_NAME}" >&2
  exit 1
fi
if [[ -z "${ROLE_NAME}" || "${ROLE_NAME}" == "None" ]]; then
  echo "failed to read RunsOnInstanceRoleName from CloudFormation stack: ${STACK_NAME}" >&2
  exit 1
fi

IFS=',' read -r SUBNET_ID _rest <<<"${SUBNETS_CSV}"
if [[ -z "${SUBNET_ID}" ]]; then
  echo "could not select subnet from RunsOnPublicSubnetIds: ${SUBNETS_CSV}" >&2
  exit 1
fi

INSTANCE_PROFILE_NAME="$(aws iam list-instance-profiles-for-role \
  --profile "${PROFILE}" \
  --role-name "${ROLE_NAME}" \
  --query 'InstanceProfiles[0].InstanceProfileName' \
  --output text)"
if [[ -z "${INSTANCE_PROFILE_NAME}" || "${INSTANCE_PROFILE_NAME}" == "None" ]]; then
  echo "could not find instance profile for role: ${ROLE_NAME}" >&2
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
  --block-device-mappings '[
    {
      "DeviceName": "/dev/sda1",
      "Ebs": { "VolumeSize": 200, "VolumeType": "gp3", "DeleteOnTermination": true }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-e2e-devnet-testnet},{Key=juno-intents,Value=e2e-devnet-testnet}]' \
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

echo "running e2e via SSM..." >&2
export REGION INSTANCE_ID RUST_TOOLCHAIN RISC0_RUST_TOOLCHAIN RZUP_VERSION RISC0_GROTH16_VERSION GO_VERSION GIT_SHA DEPLOYMENT_NAME
COMMAND_ID="$(
  python3 - <<'PY'
import json
import os
import subprocess

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
deployment = os.environ["DEPLOYMENT_NAME"]
git_sha = os.environ["GIT_SHA"]

rust_toolchain = os.environ["RUST_TOOLCHAIN"]
risc0_rust_toolchain = os.environ["RISC0_RUST_TOOLCHAIN"]
rzup_version = os.environ["RZUP_VERSION"]
risc0_groth16_version = os.environ["RISC0_GROTH16_VERSION"]
go_version = os.environ.get("GO_VERSION", "1.22.6")

cmds = [
    "set -euo pipefail",
    "if ! command -v git >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends git; fi",
    "if ! command -v curl >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends curl; fi",
    "if ! command -v protoc >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends protobuf-compiler; fi",
    "if ! command -v docker >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends docker.io; fi",
    "sudo systemctl start docker || sudo service docker start || true",
    "docker ps >/dev/null",
    f"if ! command -v go >/dev/null || ! go version | grep -q 'go{go_version}'; then curl -sSfL https://go.dev/dl/go{go_version}.linux-amd64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz; fi",
    'export PATH="/usr/local/go/bin:$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"',
    "go version",
    "if ! command -v cargo >/dev/null; then curl -sSf https://sh.rustup.rs | sh -s -- -y; fi",
    'export PATH="$HOME/.cargo/bin:/usr/local/go/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"',
    f"rustup toolchain install {rust_toolchain} || true",
    f"rustup default {rust_toolchain} || true",
    f"rustup toolchain install {risc0_rust_toolchain} || true",
    f"if ! command -v rzup >/dev/null || ! rzup --version | grep -q '{rzup_version}'; then cargo install rzup --version {rzup_version} --locked --force; fi",
    f"rzup install rust {risc0_rust_toolchain}",
    f"rzup install risc0-groth16 {risc0_groth16_version}",
    "if ! command -v solana >/dev/null; then sh -c \"$(curl -sSfL https://release.solana.com/stable/install)\"; fi",
    'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"',
    "solana --version",
    "spl-token --version",
    "rm -rf juno-intents && git clone https://github.com/Abdullah1738/juno-intents.git",
    "cd juno-intents",
    f"git checkout {git_sha}",
    f"./scripts/e2e/devnet-testnet.sh --deployment {deployment}",
]

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
)"

echo "ssm command id: ${COMMAND_ID}" >&2
echo "waiting for command to finish..." >&2
awsj ssm wait command-executed --command-id "${COMMAND_ID}" --instance-id "${INSTANCE_ID}" || true

status="$(awsj ssm get-command-invocation \
  --command-id "${COMMAND_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query 'Status' \
  --output text)"
echo "ssm status: ${status}" >&2

if [[ "${status}" != "Success" ]]; then
  awsj ssm get-command-invocation \
    --command-id "${COMMAND_ID}" \
    --instance-id "${INSTANCE_ID}" \
    --query '{Status:Status,Stdout:StandardOutputContent,Stderr:StandardErrorContent}' \
    --output json >&2 || true
  exit 1
fi

awsj ssm get-command-invocation \
  --command-id "${COMMAND_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query '{Stdout:StandardOutputContent,Stderr:StandardErrorContent}' \
  --output json >&2

echo "done" >&2

