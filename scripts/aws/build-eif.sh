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

DOWNLOAD_DIR="${JUNO_EIF_DOWNLOAD_DIR:-}"
REMOTE_HTTP_PORT="${JUNO_EIF_HTTP_PORT:-18080}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/build-eif.sh [--ref <git-ref>] [--download-dir <path>]

Environment:
  JUNO_AWS_REGION             (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME     (default: runs-on)
  JUNO_EIF_EC2_AMI_ID         (default: al2023 us-east-1 pinned)
  JUNO_EIF_EC2_INSTANCE_TYPE  (default: c6i.large)
  JUNO_EIF_GIT_REPO           (default: Abdullah1738/juno-intents)
  JUNO_EIF_GIT_REF            (default: current HEAD if available, else main)
  JUNO_EIF_DOWNLOAD_DIR       (default: empty; do not download)
  JUNO_EIF_HTTP_PORT          (default: 18080; remote instance-only HTTP server port for downloads)

Notes:
  - All AWS calls use: --profile juno
  - The instance is ALWAYS terminated on exit (success/failure).
  - Prints git_sha/pcr0/eif_sha256 to stdout.
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
    --download-dir)
      DOWNLOAD_DIR="${2:-}"
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
  python3 - <<'PYGEN'
import json
import os
import subprocess

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
repo = os.environ["REPO"]
ref = os.environ["REF"]

pcr0_cmd = r"""PCR0="$(python3 -c 'import re,sys; s=sys.stdin.read(); m=re.search(r"PCR0[^0-9a-fA-F]*([0-9a-fA-F]{96})", s, re.I); print(m.group(1) if m else "")' <<<"${DESCRIBE_OUT}" 2>/dev/null || true)" """

meta_cmd = r"""python3 - <<'PYMETA' > tmp/enclave/operator.meta.json
import json, os, datetime
meta={
  "git_sha": os.environ.get("GIT_SHA",""),
  "pcr0": (os.environ.get("PCR0","") or "").lower(),
  "eif_sha256": (os.environ.get("EIF_SHA256","") or "").lower(),
  "operator_sha256": (os.environ.get("OPERATOR_SHA256","") or "").lower(),
  "nitro_cli_version": os.environ.get("NITRO_CLI_VERSION",""),
  "built_at_utc": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
}
print(json.dumps(meta, indent=2, sort_keys=True))
PYMETA"""

cmds = [
    "set -euo pipefail",
    "cd /tmp",
    "sudo dnf install -y git docker python3",
    "sudo systemctl enable --now docker",
    "docker --version",
    # Nitro CLI (package names differ across repos/versions).
    "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel || sudo dnf install -y aws-nitro-enclaves-cli",
    "sudo dnf install -y nitro-enclaves-cli nitro-enclaves-cli-devel || sudo dnf install -y nitro-enclaves-cli || true",
    "nitro-cli --version || true",
    "nitro-cli build-enclave --help || true",
    "ls -la /usr/share/nitro_enclaves || true",
    "find /usr/share/nitro_enclaves -maxdepth 3 -type f | head -n 200 || true",
    f"rm -rf juno-intents && git clone https://github.com/{repo}.git juno-intents",
    "cd juno-intents",
    f"git checkout {ref}",
    "scripts/enclave/build-eif.sh",
    "GIT_SHA=\"$(git rev-parse HEAD)\"",
    "DESCRIBE_OUT=\"$(nitro-cli describe-eif --eif-path tmp/enclave/operator.eif 2>&1)\"",
    pcr0_cmd,
    "EIF_SHA256=\"$(sha256sum tmp/enclave/operator.eif | awk '{print $1}')\"",
    "IMAGE_TAG=\"juno-intents/nitro-operator-enclave:$(git rev-parse --short HEAD)\"",
    "CID=\"$(docker create \"${IMAGE_TAG}\")\"",
    "docker cp \"${CID}:/operator\" /tmp/juno-operator",
    "docker rm -f \"${CID}\" >/dev/null",
    "OPERATOR_SHA256=\"$(sha256sum /tmp/juno-operator | awk '{print $1}')\"",
    "NITRO_CLI_VERSION=\"$(nitro-cli --version 2>&1 | tr '\\n' ' ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/[[:space:]]$//')\"",
    "export GIT_SHA PCR0 EIF_SHA256 OPERATOR_SHA256 NITRO_CLI_VERSION",
    meta_cmd,
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
PYGEN
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
    --query '{Stdout:StandardOutputContent,Stderr:StandardErrorContent}' \
    --output json >&2 || true
  exit 1
fi

if [[ -n "${DOWNLOAD_DIR}" ]]; then
  if ! command -v session-manager-plugin >/dev/null; then
    echo "missing required command: session-manager-plugin" >&2
    exit 1
  fi
  if ! command -v curl >/dev/null; then
    echo "missing required command: curl" >&2
    exit 1
  fi

  mkdir -p "${DOWNLOAD_DIR}"

  echo "starting HTTP file server on instance..." >&2
  export REMOTE_HTTP_PORT
  SERVER_COMMAND_ID="$(
    python3 - <<'PY'
import json, os, subprocess
region=os.environ["REGION"]
instance_id=os.environ["INSTANCE_ID"]
port=os.environ["REMOTE_HTTP_PORT"]
cmds=[
  "set -euo pipefail",
  "cd /tmp/juno-intents/tmp/enclave",
  "rm -f /tmp/juno-eif-http.pid",
  f"nohup python3 -m http.server {port} --bind 127.0.0.1 --directory . >/tmp/juno-eif-http.log 2>&1 & echo $! > /tmp/juno-eif-http.pid",
  "sleep 1",
  "echo http_started=1",
]
payload=json.dumps({"commands":cmds})
out=subprocess.check_output([
  "aws","--profile","juno","--region",region,
  "ssm","send-command",
  "--document-name","AWS-RunShellScript",
  "--targets",f"Key=InstanceIds,Values={instance_id}",
  "--parameters",payload,
  "--query","Command.CommandId",
  "--output","text",
], text=True)
print(out.strip())
PY
  )"
  awsj ssm wait command-executed --command-id "${SERVER_COMMAND_ID}" --instance-id "${INSTANCE_ID}" || true

  server_status="$(awsj ssm get-command-invocation --command-id "${SERVER_COMMAND_ID}" --instance-id "${INSTANCE_ID}" --query 'Status' --output text 2>/dev/null || true)"
  if [[ "${server_status}" != "Success" ]]; then
    echo "failed to start HTTP server (status=${server_status})" >&2
    awsj ssm get-command-invocation --command-id "${SERVER_COMMAND_ID}" --instance-id "${INSTANCE_ID}" --query '{Stdout:StandardOutputContent,Stderr:StandardErrorContent}' --output json 2>/dev/null || true
    exit 1
  fi

  LOCAL_PORT="$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
PY
)"

  echo "port-forwarding localhost:${LOCAL_PORT} -> instance:${REMOTE_HTTP_PORT} (ssm)..." >&2
  aws --profile "${PROFILE}" --region "${REGION}" ssm start-session \
    --target "${INSTANCE_ID}" \
    --document-name AWS-StartPortForwardingSession \
    --parameters "{\"portNumber\":[\"${REMOTE_HTTP_PORT}\"],\"localPortNumber\":[\"${LOCAL_PORT}\"]}" \
    >/tmp/juno-eif-portforward.log 2>&1 &
  pf_pid=$!

  download_one() {
    local name="$1"
    local dst="$2"
    for _ in $(seq 1 60); do
      if curl -fsS "http://127.0.0.1:${LOCAL_PORT}/${name}" -o "${dst}"; then
        return 0
      fi
      sleep 1
    done
    return 1
  }

  echo "downloading operator.eif + operator.meta.json..." >&2
  if ! download_one "operator.meta.json" "${DOWNLOAD_DIR}/operator.meta.json"; then
    echo "failed to download operator.meta.json" >&2
    kill "${pf_pid}" >/dev/null 2>&1 || true
    exit 1
  fi
  if ! download_one "operator.eif" "${DOWNLOAD_DIR}/operator.eif"; then
    echo "failed to download operator.eif" >&2
    kill "${pf_pid}" >/dev/null 2>&1 || true
    exit 1
  fi

  kill "${pf_pid}" >/dev/null 2>&1 || true
  wait "${pf_pid}" >/dev/null 2>&1 || true

  echo "stopping HTTP server..." >&2
  STOP_COMMAND_ID="$(
    python3 - <<'PY'
import json, os, subprocess
region=os.environ["REGION"]
instance_id=os.environ["INSTANCE_ID"]
cmds=[
  "set -euo pipefail",
  "if [ -f /tmp/juno-eif-http.pid ]; then kill \"$(cat /tmp/juno-eif-http.pid)\" >/dev/null 2>&1 || true; fi",
]
payload=json.dumps({"commands":cmds})
out=subprocess.check_output([
  "aws","--profile","juno","--region",region,
  "ssm","send-command",
  "--document-name","AWS-RunShellScript",
  "--targets",f"Key=InstanceIds,Values={instance_id}",
  "--parameters",payload,
  "--query","Command.CommandId",
  "--output","text",
], text=True)
print(out.strip())
PY
  )"
  awsj ssm wait command-executed --command-id "${STOP_COMMAND_ID}" --instance-id "${INSTANCE_ID}" || true

  echo "eif_local_path=${DOWNLOAD_DIR}/operator.eif"
  echo "meta_local_path=${DOWNLOAD_DIR}/operator.meta.json"

  KV_OUT="$(python3 - <<'PY' "${DOWNLOAD_DIR}/operator.meta.json"
import json,sys
path=sys.argv[1]
with open(path,"r",encoding="utf-8") as f:
  meta=json.load(f)
for k in ("git_sha","pcr0","eif_sha256"):
  v=meta.get(k) or ""
  print(f"{k}={v}")
PY
)"
  printf '%s\n' "${KV_OUT}"

  git_sha="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^git_sha=(.+)$/\1/p' | head -n 1)"
  pcr0="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^pcr0=(.+)$/\1/p' | head -n 1)"
  eif_sha256="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^eif_sha256=(.+)$/\1/p' | head -n 1)"

  local_sha="$(
    python3 - <<'PY' "${DOWNLOAD_DIR}/operator.eif"
import hashlib,sys
path=sys.argv[1]
h=hashlib.sha256()
with open(path,"rb") as f:
  for chunk in iter(lambda: f.read(1024*1024), b""):
    h.update(chunk)
print(h.hexdigest())
PY
  )"
  if [[ -z "${eif_sha256}" || "${local_sha}" != "${eif_sha256}" ]]; then
    echo "EIF sha256 mismatch (meta=${eif_sha256} local=${local_sha})" >&2
    exit 1
  fi
else
  echo "fetching build metadata via SSM..." >&2
  META_COMMAND_ID="$(
    python3 - <<'PY'
import json, os, subprocess
region=os.environ["REGION"]
instance_id=os.environ["INSTANCE_ID"]
cmds=[
  "set -euo pipefail",
  "cat /tmp/juno-intents/tmp/enclave/operator.meta.json",
]
payload=json.dumps({"commands":cmds})
out=subprocess.check_output([
  "aws","--profile","juno","--region",region,
  "ssm","send-command",
  "--document-name","AWS-RunShellScript",
  "--targets",f"Key=InstanceIds,Values={instance_id}",
  "--parameters",payload,
  "--query","Command.CommandId",
  "--output","text",
], text=True)
print(out.strip())
PY
  )"
  awsj ssm wait command-executed --command-id "${META_COMMAND_ID}" --instance-id "${INSTANCE_ID}" || true
  meta_status="$(awsj ssm get-command-invocation --command-id "${META_COMMAND_ID}" --instance-id "${INSTANCE_ID}" --query 'Status' --output text 2>/dev/null || true)"
  if [[ "${meta_status}" != "Success" ]]; then
    echo "failed to fetch metadata (status=${meta_status})" >&2
    awsj ssm get-command-invocation --command-id "${META_COMMAND_ID}" --instance-id "${INSTANCE_ID}" --query '{Stdout:StandardOutputContent,Stderr:StandardErrorContent}' --output json 2>/dev/null >&2 || true
    exit 1
  fi

  meta_inv="$(awsj ssm get-command-invocation --command-id "${META_COMMAND_ID}" --instance-id "${INSTANCE_ID}" --query '{Stdout:StandardOutputContent,Stderr:StandardErrorContent}' --output json)"
  export META_INV_JSON="${meta_inv}"
  KV_OUT="$(python3 - <<'PY'
import json, os

obj = json.loads(os.environ["META_INV_JSON"])
stdout = (obj.get("Stdout") or "").strip()
if not stdout:
  raise SystemExit(1)

meta = json.loads(stdout)
for k in ("git_sha", "pcr0", "eif_sha256"):
  v = (meta.get(k) or "").strip()
  if not v:
    raise SystemExit(2)
  print(f"{k}={v}")
PY
)"
  unset META_INV_JSON
  if [[ -z "${KV_OUT}" ]]; then
    echo "failed to parse operator.meta.json from SSM output" >&2
    printf '%s\n' "${meta_inv}" >&2
    exit 1
  fi
  printf '%s\n' "${KV_OUT}"
fi
