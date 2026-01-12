#!/usr/bin/env bash
set -euo pipefail

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Default to the RunsOn GPU AMI observed in CI logs (us-east-1).
# Override via JUNO_EC2_AMI_ID if you rotate images.
AMI_ID="${JUNO_EC2_AMI_ID:-ami-06d69846519cd5d6f}"
INSTANCE_TYPE="${JUNO_EC2_INSTANCE_TYPE:-g5.4xlarge}"

RUST_TOOLCHAIN="${JUNO_RUST_TOOLCHAIN:-1.91.1}"
RISC0_RUST_TOOLCHAIN="${JUNO_RISC0_RUST_TOOLCHAIN:-1.91.1}"
RZUP_VERSION="${JUNO_RZUP_VERSION:-0.5.1}"
RISC0_GROTH16_VERSION="${JUNO_RISC0_GROTH16_VERSION:-0.1.0}"
GO_VERSION="${JUNO_GO_VERSION:-1.22.6}"
MODE="${JUNO_PROVE_MODE:-all}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/prove-groth16.sh [--mode synthetic|real|all]

Environment:
  JUNO_AWS_REGION             (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME     (default: runs-on)
  JUNO_EC2_AMI_ID             (default: ami-06d69846519cd5d6f)
  JUNO_EC2_INSTANCE_TYPE      (default: g5.4xlarge)
  JUNO_PROVE_MODE             (default: all)

Notes:
  - All AWS calls use: --profile juno
  - The instance is ALWAYS terminated on exit (success/failure).
  - This runs Groth16 CUDA proving (synthetic and/or regtest witness).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done
case "${MODE}" in
  synthetic|real|all) ;;
  *)
    echo "invalid --mode: ${MODE}" >&2
    usage
    exit 2
    ;;
esac

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
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-prover},{Key=juno-intents,Value=prove-groth16}]' \
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

echo "running prove command via SSM..." >&2
export REGION INSTANCE_ID RUST_TOOLCHAIN RISC0_RUST_TOOLCHAIN RZUP_VERSION RISC0_GROTH16_VERSION GO_VERSION MODE
COMMAND_ID="$(
  python3 - <<'PY'
import json
import os
import subprocess

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
rust_toolchain = os.environ["RUST_TOOLCHAIN"]
risc0_rust_toolchain = os.environ["RISC0_RUST_TOOLCHAIN"]
rzup_version = os.environ["RZUP_VERSION"]
risc0_groth16_version = os.environ["RISC0_GROTH16_VERSION"]
go_version = os.environ.get("GO_VERSION", "1.22.6")
mode = os.environ.get("MODE", "all")

cmds = [
    "set -euo pipefail",
    "if ! command -v git >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends git; fi",
    "if ! command -v curl >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends curl; fi",
    "if ! command -v protoc >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends protobuf-compiler; fi",
    "if ! command -v docker >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends docker.io; fi",
    "sudo systemctl start docker || sudo service docker start || true",
    "docker --version",
    "docker ps >/dev/null",
    f"if ! command -v go >/dev/null || ! go version | grep -q 'go{go_version}'; then curl -sSfL https://go.dev/dl/go{go_version}.linux-amd64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz; fi",
    'export PATH="/usr/local/go/bin:$HOME/.cargo/bin:$PATH"',
    "go version",
    "if ! command -v cargo >/dev/null; then curl -sSf https://sh.rustup.rs | sh -s -- -y; fi",
    'export PATH=\"$HOME/.cargo/bin:/usr/local/go/bin:$PATH\"',
    f"rustup toolchain install {rust_toolchain} || true",
    f"rustup default {rust_toolchain} || true",
    f"rustup toolchain install {risc0_rust_toolchain} || true",
    "rm -rf juno-intents && git clone --depth 1 https://github.com/Abdullah1738/juno-intents.git",
    "cd juno-intents",
    f"if ! command -v rzup >/dev/null || ! rzup --version | grep -q '{rzup_version}'; then cargo install rzup --version {rzup_version} --locked --force; fi",
    f"rzup install rust {risc0_rust_toolchain}",
    f"rzup install risc0-groth16 {risc0_groth16_version}",
]

if mode in ("synthetic", "all"):
    cmds.append(
        "time cargo test --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --test groth16_bundle -- --ignored --nocapture"
    )

if mode in ("real", "all"):
    cmds.extend(
        [
            'DEPLOYMENT_ID_HEX="$(printf \'11%.0s\' {1..32})"',
            'INTENT_NONCE_HEX="$(printf \'33%.0s\' {1..32})"',
            'IEP_PROGRAM_ID_HEX="$(printf \'a1%.0s\' {1..32})"',
            'FILL_ID_HEX="$(go run ./cmd/juno-intents pda --program-id "${IEP_PROGRAM_ID_HEX}" --deployment-id "${DEPLOYMENT_ID_HEX}" --intent-nonce "${INTENT_NONCE_HEX}" --print fill-id-hex)"',
            'W="$(scripts/junocash/regtest/witness-hex.sh --deployment-id "${DEPLOYMENT_ID_HEX}" --fill-id "${FILL_ID_HEX}")"',
            'export JUNO_RECEIPT_WITNESS_HEX="${W}"',
            "time cargo test --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --test groth16_real_witness -- --ignored --nocapture",
            'BUNDLE_HEX="$(cargo run --release --locked --manifest-path risc0/receipt/host/Cargo.toml --features cuda --bin prove_bundle_v1)"',
            'export JUNO_RECEIPT_ZKVM_BUNDLE_HEX="${BUNDLE_HEX}"',
            "cargo test --locked --manifest-path solana/Cargo.toml -p juno-intents-receipt-verifier --test e2e_risc0_groth16_bundle -- --ignored --nocapture",
            "cargo test --locked --manifest-path solana/Cargo.toml -p juno-intents-intent-escrow --test e2e_risc0_groth16_settle -- --ignored --nocapture",
        ]
    )

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
