#!/usr/bin/env bash
set -euo pipefail

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Pin to a concrete AL2023 AMI (us-east-1) for repeatable tooling.
AMI_ID="${JUNO_EIF_EC2_AMI_ID:-ami-07ff62358b87c7116}"
INSTANCE_TYPE="${JUNO_EIF_EC2_INSTANCE_TYPE:-c6i.large}"

REPO="${JUNO_EIF_GIT_REPO:-Abdullah1738/juno-intents}"
REF="${JUNO_EIF_GIT_REF:-}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/build-eif.sh [--ref <git-ref>]

Environment:
  JUNO_AWS_REGION             (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME     (default: runs-on)
  JUNO_EIF_EC2_AMI_ID         (default: al2023 us-east-1 pinned)
  JUNO_EIF_EC2_INSTANCE_TYPE  (default: c6i.large)
  JUNO_EIF_GIT_REPO           (default: Abdullah1738/juno-intents)
  JUNO_EIF_GIT_REF            (default: current HEAD if available, else main)

Notes:
  - All AWS calls use: --profile juno
  - The instance is ALWAYS terminated on exit (success/failure).
  - This prints PCR0 to stderr when successful.
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

if [[ -z "${REF}" ]]; then
  if git rev-parse HEAD >/dev/null 2>&1; then
    REF="$(git rev-parse HEAD)"
  else
    REF="main"
  fi
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
      "DeviceName": "/dev/xvda",
      "Ebs": { "VolumeSize": 80, "VolumeType": "gp3", "DeleteOnTermination": true }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-eif-builder},{Key=juno-intents,Value=build-eif}]' \
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

echo "building EIF via SSM..." >&2
export REGION INSTANCE_ID REPO REF
COMMAND_ID="$(
  python3 - <<'PY'
import json
import os
import subprocess

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
repo = os.environ["REPO"]
ref = os.environ["REF"]

cmds = [
    "set -euo pipefail",
    "sudo dnf install -y git docker python3",
    "sudo systemctl enable --now docker",
    "docker --version",
    # Nitro CLI (package name differs across repos/versions).
    "sudo dnf install -y aws-nitro-enclaves-cli || sudo dnf install -y nitro-enclaves-cli",
    "nitro-cli --version || true",
    f"rm -rf juno-intents && git clone https://github.com/{repo}.git juno-intents",
    "cd juno-intents",
    f"git checkout {ref}",
    "scripts/enclave/build-eif.sh",
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

invocation="$(awsj ssm get-command-invocation \
  --command-id "${COMMAND_ID}" \
  --instance-id "${INSTANCE_ID}" \
  --query '{Stdout:StandardOutputContent,Stderr:StandardErrorContent}' \
  --output json)"

echo "${invocation}" >&2

if [[ "${status}" != "Success" ]]; then
  exit 1
fi

PY_OUT="$(python3 - <<'PY' <<<"${invocation}" || true
import json,sys,re
obj=json.load(sys.stdin)
stderr=obj.get("Stderr","")
m=re.search(r\"^pcr0=([0-9a-fA-F]+)$\", stderr, re.M)
if m:
    print(m.group(1))
PY
)"

if [[ -n "${PY_OUT}" ]]; then
  echo "PCR0=${PY_OUT}" >&2
fi

