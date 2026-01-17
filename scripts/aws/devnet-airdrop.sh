#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Pin to a concrete AL2023 AMI (us-east-1) for repeatability.
AMI_ID="${JUNO_AIRDROP_AMI_ID:-ami-07ff62358b87c7116}"
INSTANCE_TYPE="${JUNO_AIRDROP_INSTANCE_TYPE:-t3.micro}"
INSTANCE_PROFILE_NAME="${JUNO_NITRO_INSTANCE_PROFILE_NAME:-}"

RPC_URL="${SOLANA_RPC_URL:-https://api.devnet.solana.com}"
PUBKEY=""
TARGET_LAMPORTS=""
CHUNK_LAMPORTS="1000000000"
SSM_TIMEOUT_SECONDS="${JUNO_SSM_TIMEOUT_SECONDS:-7200}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/devnet-airdrop.sh --pubkey <base58> --sol <amount>
  scripts/aws/devnet-airdrop.sh --pubkey <base58> --lamports <amount>

Environment:
  JUNO_AWS_REGION                  (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME          (default: runs-on)
  JUNO_AIRDROP_AMI_ID              (default: pinned AL2023 us-east-1)
  JUNO_AIRDROP_INSTANCE_TYPE       (default: t3.micro)
  JUNO_NITRO_INSTANCE_PROFILE_NAME (default: terraform output instance_profile_name, else juno-intents-nitro-operator)
  JUNO_SSM_TIMEOUT_SECONDS         (default: 7200)
  SOLANA_RPC_URL                   (default: https://api.devnet.solana.com)

Notes:
  - Uses AWS SSM from a fresh EC2 instance to request devnet airdrops from a different IP.
  - Always terminates the instance on exit.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --pubkey)
      PUBKEY="${2:-}"; shift 2 ;;
    --sol)
      TARGET_LAMPORTS="$(python3 -c 'import sys; print(int(float(sys.argv[1]) * 1_000_000_000))' "${2:-}")"
      shift 2
      ;;
    --lamports)
      TARGET_LAMPORTS="${2:-}"; shift 2 ;;
    --chunk-sol)
      CHUNK_LAMPORTS="$(python3 -c 'import sys; print(int(float(sys.argv[1]) * 1_000_000_000))' "${2:-}")"
      shift 2
      ;;
    --chunk-lamports)
      CHUNK_LAMPORTS="${2:-}"; shift 2 ;;
    --rpc-url)
      RPC_URL="${2:-}"; shift 2 ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${PUBKEY}" ]]; then
  echo "--pubkey is required" >&2
  exit 2
fi
if [[ -z "${TARGET_LAMPORTS}" ]]; then
  echo "one of --sol or --lamports is required" >&2
  exit 2
fi
if [[ "${TARGET_LAMPORTS}" -le 0 ]]; then
  echo "target must be > 0" >&2
  exit 2
fi
if [[ "${CHUNK_LAMPORTS}" -le 0 ]]; then
  echo "chunk must be > 0" >&2
  exit 2
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
  --block-device-mappings '[
    {
      "DeviceName": "/dev/xvda",
      "Ebs": { "VolumeSize": 30, "VolumeType": "gp3", "DeleteOnTermination": true }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-devnet-airdrop},{Key=juno-intents,Value=devnet-airdrop}]' \
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

export REGION INSTANCE_ID PUBKEY RPC_URL TARGET_LAMPORTS CHUNK_LAMPORTS

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
    "--instance-ids",
    instance_id,
    "--document-name",
    "AWS-RunShellScript",
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
  local loops="$(( (SSM_TIMEOUT_SECONDS + 1) / 2 ))"
  for _ in $(seq 1 "${loops}"); do
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
        sleep 2
        ;;
    esac
  done
  echo "${status}"
}

REMOTE_CMDS="$(
  python3 - <<'PY'
import json, os
rpc_url=os.environ["RPC_URL"]
pubkey=os.environ["PUBKEY"]
target=os.environ["TARGET_LAMPORTS"]
chunk=os.environ["CHUNK_LAMPORTS"]

python_code = r"""import json
import os
import time
import urllib.request

rpc_url = os.environ["RPC_URL"]
pubkey = os.environ["PUBKEY"]
target = int(os.environ["TARGET_LAMPORTS"])
chunk = int(os.environ["CHUNK_LAMPORTS"])

def rpc(method, params):
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    data = json.dumps(req).encode()
    r = urllib.request.Request(rpc_url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=30) as resp:
        out = json.loads(resp.read().decode())
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]

def get_balance():
    res = rpc("getBalance", [pubkey, {"commitment": "confirmed"}])
    return int(res["value"])

attempts = 0
sleep_s = 6
bal = get_balance()
print(f"balance={bal} target={target} pubkey={pubkey} rpc={rpc_url}")

while bal < target and attempts < 120:
    attempts += 1
    try:
        sig = rpc("requestAirdrop", [pubkey, chunk])
        print(f"airdrop[{attempts}] sig={sig}")
        sleep_s = 15
    except Exception as e:
        msg = str(e)
        print(f"airdrop[{attempts}] error={msg}")
        if "429" in msg or "Too Many Requests" in msg:
            sleep_s = min(sleep_s * 2, 120)
        else:
            sleep_s = min(max(sleep_s, 15), 120)
    time.sleep(sleep_s)
    bal = get_balance()
    print(f"balance={bal}")

if bal < target:
    raise SystemExit(f"still underfunded: balance={bal} target={target}")

print("funded")
"""

cmd = "\n".join(
    [
        "set -euo pipefail",
        f"export RPC_URL='{rpc_url}'",
        f"export PUBKEY='{pubkey}'",
        f"export TARGET_LAMPORTS='{target}'",
        f"export CHUNK_LAMPORTS='{chunk}'",
        "python3 - <<'PY2'",
        python_code,
        "PY2",
    ]
)
print(json.dumps([cmd]))
PY
)"

echo "requesting airdrop via remote EC2 (pubkey=${PUBKEY})..." >&2
CMD_ID="$(send_ssm "${REMOTE_CMDS}")"
echo "ssm command id: ${CMD_ID}" >&2
status="$(wait_ssm "${CMD_ID}")"
echo "ssm status: ${status}" >&2

stdout="$(awsj ssm get-command-invocation --command-id "${CMD_ID}" --instance-id "${INSTANCE_ID}" --query 'StandardOutputContent' --output text || true)"
stderr="$(awsj ssm get-command-invocation --command-id "${CMD_ID}" --instance-id "${INSTANCE_ID}" --query 'StandardErrorContent' --output text || true)"

if [[ -n "${stdout}" && "${stdout}" != "None" ]]; then
  echo "${stdout}"
fi
if [[ -n "${stderr}" && "${stderr}" != "None" ]]; then
  echo "${stderr}" >&2
fi

if [[ "${status}" != "Success" ]]; then
  exit 1
fi
