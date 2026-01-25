#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

# Default to the RunsOn GPU AMI observed in CI logs (us-east-1).
# Override via JUNO_E2E_EC2_AMI_ID if you rotate images.
AMI_ID="${JUNO_E2E_EC2_AMI_ID:-ami-06d69846519cd5d6f}"
INSTANCE_TYPE="${JUNO_E2E_EC2_INSTANCE_TYPE:-g5.4xlarge}"

REPO="${JUNO_E2E_GIT_REPO:-Abdullah1738/juno-intents}"
REF="${JUNO_E2E_GIT_REF:-}"

BASE_DEPLOYMENT="${JUNO_E2E_BASE_DEPLOYMENT:-devnet-tee-testnet-base}"
DEPLOYMENTS_FILE="${JUNO_E2E_DEPLOYMENTS_FILE:-deployments.json}"

KMS_KEY_ID="${JUNO_NITRO_KMS_KEY_ID:-alias/juno-intents-nitro-operator}"
KMS_VSOCK_PORT="${JUNO_NITRO_KMS_VSOCK_PORT:-8000}"

ENCLAVE_PORT="${JUNO_E2E_NITRO_PORT:-5000}"
ENCLAVE_CID1="${JUNO_E2E_NITRO_CID1:-16}"
ENCLAVE_CID2="${JUNO_E2E_NITRO_CID2:-17}"
ENCLAVE_MEM_MIB="${JUNO_E2E_NITRO_ENCLAVE_MEM_MIB:-1024}"
ENCLAVE_CPU_COUNT="${JUNO_E2E_NITRO_ENCLAVE_CPU_COUNT:-2}"

INSTANCE_PROFILE_NAME="${JUNO_NITRO_INSTANCE_PROFILE_NAME:-}"

GO_VERSION="${JUNO_GO_VERSION:-1.22.6}"
RUST_TOOLCHAIN="${JUNO_RUST_TOOLCHAIN:-1.91.1}"
RISC0_RUST_TOOLCHAIN="${JUNO_RISC0_RUST_TOOLCHAIN:-1.91.1}"
RZUP_VERSION="${JUNO_RZUP_VERSION:-0.5.1}"
RISC0_GROTH16_VERSION="${JUNO_RISC0_GROTH16_VERSION:-0.1.0}"
SOLANA_VERSION="${JUNO_SOLANA_VERSION:-v1.18.26}"

KEEP_INSTANCE="${JUNO_E2E_KEEP_INSTANCE:-0}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/e2e-devnet-testnet.sh [--ref <git-ref>] [--base-deployment <name>] [--keep-instance]

Runs the real-network E2E (Solana devnet + JunoCash testnet) on an AWS GPU instance that also runs Nitro enclaves.

Environment:
  JUNO_AWS_REGION                (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME        (default: runs-on)
  JUNO_E2E_EC2_AMI_ID            (default: ami-06d69846519cd5d6f)
  JUNO_E2E_EC2_INSTANCE_TYPE     (default: g5.4xlarge)
  JUNO_E2E_GIT_REPO              (default: Abdullah1738/juno-intents)
  JUNO_E2E_GIT_REF               (default: current HEAD if available, else main)
  JUNO_E2E_BASE_DEPLOYMENT       (default: devnet-tee-testnet-base)
  JUNO_E2E_DEPLOYMENTS_FILE      (default: deployments.json)

  JUNO_NITRO_KMS_KEY_ID          (default: alias/juno-intents-nitro-operator)
  JUNO_NITRO_KMS_VSOCK_PORT      (default: 8000)
  JUNO_E2E_NITRO_CID1            (default: 16)
  JUNO_E2E_NITRO_CID2            (default: 17)
  JUNO_E2E_NITRO_PORT            (default: 5000)
  JUNO_E2E_NITRO_ENCLAVE_MEM_MIB (default: 1024)
  JUNO_E2E_NITRO_ENCLAVE_CPU_COUNT (default: 2)

  JUNO_NITRO_INSTANCE_PROFILE_NAME (default: terraform output instance_profile_name, else juno-intents-nitro-operator)

  JUNO_GO_VERSION                (default: 1.22.6)
  JUNO_RUST_TOOLCHAIN            (default: 1.91.1)
  JUNO_RISC0_RUST_TOOLCHAIN      (default: 1.91.1)
  JUNO_RZUP_VERSION              (default: 0.5.1)
  JUNO_RISC0_GROTH16_VERSION      (default: 0.1.0)
  JUNO_SOLANA_VERSION            (default: v1.18.26)

  JUNO_E2E_KEEP_INSTANCE         (default: 0; set to 1 to keep instance for debugging)

Notes:
  - All AWS calls use: --profile juno
  - By default, the EC2 instance is terminated on exit (success/failure), unless --keep-instance.
  - This script updates terraform allowed_pcr0 for the Nitro operator KMS key to match the freshly-built EIF.
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
    --base-deployment)
      BASE_DEPLOYMENT="${2:-}"
      shift 2
      ;;
    --keep-instance)
      KEEP_INSTANCE="1"
      shift 1
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

need_cmd() {
  if ! command -v "$1" >/dev/null; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd aws
need_cmd python3
need_cmd terraform

if [[ -z "${REF}" ]]; then
  if git -C "${ROOT}" rev-parse HEAD >/dev/null 2>&1; then
    REF="$(git -C "${ROOT}" rev-parse HEAD)"
  else
    REF="main"
  fi
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
  if [[ -n "${INSTANCE_ID}" && "${KEEP_INSTANCE}" != "1" ]]; then
    echo "terminating instance: ${INSTANCE_ID}" >&2
    awsj ec2 terminate-instances --instance-ids "${INSTANCE_ID}" >/dev/null || true
  fi
  if [[ -n "${INSTANCE_ID}" && "${KEEP_INSTANCE}" == "1" ]]; then
    echo "keeping instance for debugging: ${INSTANCE_ID}" >&2
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
  local timeout_secs="${2:-3600}"
  local poll_secs="${3:-10}"
  local elapsed=0

  while true; do
    status="$(
      awsj ssm get-command-invocation \
        --command-id "${command_id}" \
        --instance-id "${INSTANCE_ID}" \
        --query 'Status' \
        --output text 2>/dev/null || true
    )"
    case "${status}" in
      Success|Cancelled|Failed|TimedOut|Cancelling)
        echo "${status}"
        return 0
        ;;
      Pending|InProgress|Delayed|"")
        ;;
      *)
        echo "${status}"
        return 0
        ;;
    esac
    if [[ "${elapsed}" -ge "${timeout_secs}" ]]; then
      echo "${status:-InProgress}"
      return 0
    fi
    sleep "${poll_secs}"
    elapsed="$((elapsed + poll_secs))"
  done
}

get_ssm_stdout() {
  local command_id="$1"
  awsj ssm get-command-invocation --command-id "${command_id}" --instance-id "${INSTANCE_ID}" --query 'StandardOutputContent' --output text 2>/dev/null || true
}

get_ssm_stderr() {
  local command_id="$1"
  awsj ssm get-command-invocation --command-id "${command_id}" --instance-id "${INSTANCE_ID}" --query 'StandardErrorContent' --output text 2>/dev/null || true
}

export REGION INSTANCE_ID

echo "SSM phase 1: install deps + build EIF + capture pcr0..." >&2
export REPO REF GO_VERSION RUST_TOOLCHAIN RISC0_RUST_TOOLCHAIN RZUP_VERSION RISC0_GROTH16_VERSION SOLANA_VERSION
PHASE1_CMDS="$(
  python3 - <<'PY'
import json,os
repo=os.environ.get("REPO","")
ref=os.environ.get("REF","")
go_version=os.environ.get("GO_VERSION","")
rust_toolchain=os.environ.get("RUST_TOOLCHAIN","")
risc0_rust_toolchain=os.environ.get("RISC0_RUST_TOOLCHAIN","")
rzup_version=os.environ.get("RZUP_VERSION","")
risc0_groth16_version=os.environ.get("RISC0_GROTH16_VERSION","")
solana_version=os.environ.get("SOLANA_VERSION","")
solana_version_num=solana_version[1:] if solana_version.startswith("v") else solana_version

cmds=[
  "set -eu",
  'export HOME="${HOME:-/root}"',
  "export DEBIAN_FRONTEND=noninteractive",
  "sudo apt-get update -qq",
  "sudo apt-get install -y -qq --no-install-recommends git ca-certificates curl jq unzip protobuf-compiler bzip2",
  "if ! command -v docker >/dev/null; then sudo apt-get install -y -qq --no-install-recommends docker.io; fi",
  "sudo systemctl start docker 2>/dev/null || sudo service docker start 2>/dev/null || true",
  "docker --version",
  "docker ps >/dev/null",
  "nvidia-smi",
  "if ! command -v nvcc >/dev/null; then sudo apt-get install -y -qq --no-install-recommends cuda-toolkit-12-9 || sudo apt-get install -y -qq --no-install-recommends cuda-toolkit || sudo apt-get install -y -qq --no-install-recommends nvidia-cuda-toolkit || true; fi",
  "nvcc --version || true",
  f"if ! command -v go >/dev/null || ! go version | grep -q 'go{go_version}'; then curl -sSfL https://go.dev/dl/go{go_version}.linux-amd64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz; fi",
  'export PATH=\"/usr/local/cuda/bin:/usr/local/cuda-12.9/bin:/usr/local/go/bin:$HOME/.cargo/bin:/opt/solana/solana-release/bin:$PATH\"',
  "go version",
  "if ! command -v cargo >/dev/null; then curl -sSf https://sh.rustup.rs | sh -s -- -y; fi",
  'export PATH=\"/usr/local/cuda/bin:/usr/local/cuda-12.9/bin:$HOME/.cargo/bin:/usr/local/go/bin:/opt/solana/solana-release/bin:$PATH\"',
  f"rustup toolchain install {rust_toolchain} || true",
  f"rustup default {rust_toolchain} || true",
  f"rustup toolchain install {risc0_rust_toolchain} || true",
  f"if ! command -v solana >/dev/null || ! solana --version | grep -q '{solana_version_num}'; then sudo rm -rf /opt/solana && sudo mkdir -p /opt/solana && curl --retry 5 --retry-all-errors -sSfL https://github.com/solana-labs/solana/releases/download/{solana_version}/solana-release-x86_64-unknown-linux-gnu.tar.bz2 -o /tmp/solana-release.tar.bz2 && sudo tar -xjf /tmp/solana-release.tar.bz2 -C /opt/solana; fi",
  "solana --version",
  "spl-token --version || true",
  # Install nitro-cli/vsock-proxy (Ubuntu images don't ship official packages).
  "if ! command -v nitro-cli >/dev/null; then sudo apt-get install -y -qq --no-install-recommends gcc make clang llvm-dev libclang-dev linux-modules-extra-aws; fi",
  "if ! command -v nitro-cli >/dev/null; then rm -rf /tmp/aws-nitro-enclaves-cli && git clone --depth 1 https://github.com/aws/aws-nitro-enclaves-cli.git /tmp/aws-nitro-enclaves-cli; fi",
  "if ! command -v nitro-cli >/dev/null; then cd /tmp/aws-nitro-enclaves-cli && (make nitro-cli && make vsock-proxy && sudo make install NITRO_CLI_INSTALL_DIR=/usr/local) >/tmp/nitro-cli-build.log 2>&1 && cd /tmp; fi",
  "if [ -f /tmp/nitro-cli-build.log ]; then tail -n 60 /tmp/nitro-cli-build.log >&2 || true; fi",
  "if [ -f /usr/local/etc/profile.d/nitro-cli-env.sh ]; then . /usr/local/etc/profile.d/nitro-cli-env.sh; fi",
  "nitro-cli --version || true",
  "if ! command -v nitro-cli >/dev/null; then echo 'missing nitro-cli (build/install failed)' >&2; exit 1; fi",
  "VSOCK_PROXY=\"$(command -v vsock-proxy || command -v nitro-enclaves-vsock-proxy || true)\"",
  "if [ -z \"${VSOCK_PROXY}\" ]; then echo \"missing vsock-proxy\" >&2; exit 1; fi",
  "echo \"vsock-proxy=${VSOCK_PROXY}\"",
  "rm -rf /tmp/juno-intents && git clone https://github.com/" + repo + ".git /tmp/juno-intents",
  "cd /tmp/juno-intents",
  "git checkout " + ref,
  f"if ! command -v rzup >/dev/null || ! rzup --version | grep -q '{rzup_version}'; then cargo install rzup --version {rzup_version} --locked --force; fi",
  f"rzup install rust {risc0_rust_toolchain}",
  f"rzup install risc0-groth16 {risc0_groth16_version}",
  "scripts/enclave/build-eif.sh >/tmp/build-eif.log 2>&1",
  "pcr0=\"$(sed -nE 's/^pcr0=([0-9a-fA-F]{96}).*/\\\\1/p' /tmp/build-eif.log | head -n 1 | tr 'A-F' 'a-f' || true)\"",
  "if [ -z \"${pcr0}\" ]; then echo 'failed to extract pcr0 from /tmp/build-eif.log' >&2; tail -n 200 /tmp/build-eif.log >&2 || true; exit 1; fi",
  "echo \"pcr0=${pcr0}\"",
  "tail -n 60 /tmp/build-eif.log >&2 || true",
]
print(json.dumps(cmds))
PY
)"

PHASE1_ID="$(send_ssm "${PHASE1_CMDS}")"
echo "ssm phase1 command id: ${PHASE1_ID}" >&2
phase1_status="$(wait_ssm "${PHASE1_ID}" 7200 10)"
echo "ssm phase1 status: ${phase1_status}" >&2
phase1_stdout="$(get_ssm_stdout "${PHASE1_ID}")"
phase1_stderr="$(get_ssm_stderr "${PHASE1_ID}")"
printf '%s\n' "${phase1_stdout}" >&2
printf '%s\n' "${phase1_stderr}" >&2
if [[ "${phase1_status}" != "Success" ]]; then
  exit 1
fi

pcr0="$(
  printf '%s\n%s\n' "${phase1_stdout}" "${phase1_stderr}" \
    | tr -d '\r' \
    | sed -nE 's/^pcr0=([0-9a-fA-F]{96}).*/\\1/p' \
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

echo "SSM phase 2: run 2 enclaves + init keys + run e2e..." >&2
export BASE_DEPLOYMENT DEPLOYMENTS_FILE KMS_KEY_ID KMS_VSOCK_PORT ENCLAVE_PORT ENCLAVE_CID1 ENCLAVE_CID2 ENCLAVE_MEM_MIB ENCLAVE_CPU_COUNT
PHASE2_CMDS="$(
  python3 - <<'PY'
import json,os
region=os.environ["REGION"]
base=os.environ["BASE_DEPLOYMENT"]
deployments=os.environ["DEPLOYMENTS_FILE"]
kms_key_id=os.environ["KMS_KEY_ID"]
kms_vsock_port=os.environ["KMS_VSOCK_PORT"]
enclave_port=os.environ["ENCLAVE_PORT"]
cid1=os.environ["ENCLAVE_CID1"]
cid2=os.environ["ENCLAVE_CID2"]
mem=os.environ["ENCLAVE_MEM_MIB"]
cpu=os.environ["ENCLAVE_CPU_COUNT"]

cmds=[
  "set -eu",
  'export HOME="${HOME:-/root}"',
  'export PATH=\"/usr/local/cuda/bin:/usr/local/cuda-12.9/bin:/usr/local/go/bin:$HOME/.cargo/bin:/opt/solana/solana-release/bin:$PATH\"',
  "if [ -f /usr/local/etc/profile.d/nitro-cli-env.sh ]; then . /usr/local/etc/profile.d/nitro-cli-env.sh; fi",
  "cd /tmp/juno-intents",
  # Configure enclave allocator (best-effort; exact service name differs by distro).
  "sudo mkdir -p /etc/nitro_enclaves",
  f"printf '%s\\n' \"memory_mib: {int(mem)*2}\" \"cpu_count: {int(cpu)*2}\" | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null",
  "sudo systemctl restart nitro-enclaves-allocator.service 2>/dev/null || sudo systemctl restart nitro-enclaves-allocator 2>/dev/null || true",
  "sudo systemctl restart nitro-enclaves.service 2>/dev/null || sudo systemctl restart nitro-enclaves 2>/dev/null || true",
  "VSOCK_PROXY=\"$(command -v vsock-proxy || command -v nitro-enclaves-vsock-proxy || true)\"",
  "if [ -z \"${VSOCK_PROXY}\" ]; then echo \"missing vsock-proxy\" >&2; exit 1; fi",
  "echo \"vsock-proxy=${VSOCK_PROXY}\"",
  f"sudo nohup \"${{VSOCK_PROXY}}\" {kms_vsock_port} kms.{region}.amazonaws.com 443 >/var/log/vsock-proxy.log 2>&1 &",
  "sleep 1",
  # Run 2 enclaves.
  f"sudo nitro-cli run-enclave --eif-path tmp/enclave/operator.eif --cpu-count {cpu} --memory {mem} --enclave-cid {cid1}",
  f"sudo nitro-cli run-enclave --eif-path tmp/enclave/operator.eif --cpu-count {cpu} --memory {mem} --enclave-cid {cid2}",
  "sleep 2",
  "nitro-cli describe-enclaves || true",
  # Init keys for both enclaves (required for pubkey/attest).
  "mkdir -p tmp",
  "go build -trimpath -buildvcs=false -mod=readonly -ldflags \"-s -w -buildid=\" -o ./tmp/nitro-operator ./cmd/nitro-operator",
  f"./tmp/nitro-operator init-key --enclave-cid {cid1} --enclave-port {enclave_port} --region {region} --kms-key-id '{kms_key_id}' --kms-vsock-port {kms_vsock_port} --sealed-key-file ./tmp/nitro-operator-{cid1}.sealed.json",
  f"./tmp/nitro-operator init-key --enclave-cid {cid2} --enclave-port {enclave_port} --region {region} --kms-key-id '{kms_key_id}' --kms-vsock-port {kms_vsock_port} --sealed-key-file ./tmp/nitro-operator-{cid2}.sealed.json",
  # Run E2E.
  f"export JUNO_E2E_NITRO_CID1={cid1} JUNO_E2E_NITRO_CID2={cid2} JUNO_E2E_NITRO_PORT={enclave_port}",
  f"scripts/e2e/devnet-testnet.sh --base-deployment '{base}' --deployments-file '{deployments}'",
]
print(json.dumps(cmds))
PY
)"

PHASE2_ID="$(send_ssm "${PHASE2_CMDS}")"
echo "ssm phase2 command id: ${PHASE2_ID}" >&2
phase2_status="$(wait_ssm "${PHASE2_ID}" 43200 10)"
echo "ssm phase2 status: ${phase2_status}" >&2
phase2_stdout="$(get_ssm_stdout "${PHASE2_ID}")"
phase2_stderr="$(get_ssm_stderr "${PHASE2_ID}")"
printf '%s\n' "${phase2_stdout}" >&2
printf '%s\n' "${phase2_stderr}" >&2
if [[ "${phase2_status}" != "Success" ]]; then
  exit 1
fi

echo "ok" >&2
