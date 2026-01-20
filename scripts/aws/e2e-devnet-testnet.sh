#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"
LOCAL_OUT_DIR="${JUNO_E2E_LOCAL_OUT_DIR:-${ROOT}/tmp/e2e/aws}"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"
STACK_NAME="${JUNO_RUNS_ON_STACK_NAME:-runs-on}"

AMI_ID="${JUNO_E2E_AMI_ID:-ami-06d69846519cd5d6f}"
INSTANCE_TYPE="${JUNO_E2E_INSTANCE_TYPE:-g5.4xlarge}"

RUST_TOOLCHAIN="${JUNO_RUST_TOOLCHAIN:-1.91.1}"
RISC0_RUST_TOOLCHAIN="${JUNO_RISC0_RUST_TOOLCHAIN:-1.91.1}"
RZUP_VERSION="${JUNO_RZUP_VERSION:-0.5.1}"
RISC0_GROTH16_VERSION="${JUNO_RISC0_GROTH16_VERSION:-0.1.0}"
SOLANA_CLI_VERSION="${JUNO_SOLANA_CLI_VERSION:-${SOLANA_CLI_VERSION:-3.1.6}}"
GO_VERSION="${JUNO_GO_VERSION:-1.22.6}"

REF=""
DEPLOYMENT_NAME=""
CRP_MODE="${JUNO_E2E_CRP_MODE:-v1}"
PRIORITY_LEVEL="${JUNO_E2E_PRIORITY_LEVEL:-Medium}"
RUN_MODE="${JUNO_E2E_RUN_MODE:-e2e}"

SUBNET_ID="${JUNO_E2E_SUBNET_ID:-}"
SECURITY_GROUP_ID="${JUNO_E2E_SECURITY_GROUP_ID:-}"
INSTANCE_PROFILE_ARN="${JUNO_E2E_INSTANCE_PROFILE_ARN:-}"
INSTANCE_PROFILE_NAME="${JUNO_E2E_INSTANCE_PROFILE_NAME:-}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/e2e-devnet-testnet.sh --deployment <name> [--ref <git-ref>] [--crp-mode v1|v2] [--mode e2e|preflight] [--priority-level <level>]

Environment:
  JUNO_AWS_REGION            (default: us-east-1)
  JUNO_RUNS_ON_STACK_NAME    (default: runs-on)
  JUNO_E2E_AMI_ID            (default: runs-on GPU AMI)
  JUNO_E2E_INSTANCE_TYPE     (default: g5.4xlarge)
  JUNO_E2E_SUBNET_ID         (optional: override subnet discovery)
  JUNO_E2E_SECURITY_GROUP_ID (optional: override security group discovery)
  JUNO_E2E_INSTANCE_PROFILE_NAME (optional: override instance profile)
  JUNO_E2E_INSTANCE_PROFILE_ARN  (optional: override instance profile)

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
    --crp-mode)
      CRP_MODE="${2:-}"; shift 2 ;;
    --mode)
      RUN_MODE="${2:-}"; shift 2 ;;
    --priority-level)
      PRIORITY_LEVEL="${2:-}"; shift 2 ;;
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

if [[ "${CRP_MODE}" != "v1" && "${CRP_MODE}" != "v2" ]]; then
  echo "--crp-mode must be v1 or v2 (got: ${CRP_MODE})" >&2
  exit 2
fi
if [[ "${RUN_MODE}" != "e2e" && "${RUN_MODE}" != "preflight" ]]; then
  echo "--mode must be e2e or preflight (got: ${RUN_MODE})" >&2
  exit 2
fi
if [[ "${CRP_MODE}" != "v2" && "${RUN_MODE}" != "e2e" ]]; then
  echo "--mode=${RUN_MODE} is only supported with --crp-mode v2" >&2
  exit 2
fi

awsj() {
  aws --profile "${PROFILE}" --region "${REGION}" "$@"
}

imds_token() {
  curl -fsS -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true
}

imds_get() {
  local path="$1"
  local token="${2:-}"
  if [[ -z "${token}" ]]; then
    token="$(imds_token)"
  fi
  if [[ -z "${token}" ]]; then
    return 1
  fi
  curl -fsS -m 2 -H "X-aws-ec2-metadata-token: ${token}" "http://169.254.169.254/latest/${path}" 2>/dev/null
}

get_cf_output() {
  local key="$1"
  awsj cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='${key}'].OutputValue | [0]" \
    --output text 2>/dev/null || true
}

SUBNETS_CSV="$(get_cf_output RunsOnPublicSubnetIds)"
if [[ -z "${SECURITY_GROUP_ID}" ]]; then
  SECURITY_GROUP_ID="$(get_cf_output RunsOnSecurityGroupId)"
fi
ROLE_NAME="$(get_cf_output RunsOnInstanceRoleName)"

if [[ -n "${SUBNETS_CSV}" && "${SUBNETS_CSV}" != "None" && -n "${SECURITY_GROUP_ID}" && "${SECURITY_GROUP_ID}" != "None" ]]; then
  if [[ -z "${SUBNET_ID}" ]]; then
    IFS=',' read -r SUBNET_ID _rest <<<"${SUBNETS_CSV}"
  fi
fi

if [[ -z "${INSTANCE_PROFILE_ARN}" && -z "${INSTANCE_PROFILE_NAME}" && -n "${ROLE_NAME}" && "${ROLE_NAME}" != "None" ]]; then
  INSTANCE_PROFILE_NAME="$(aws iam list-instance-profiles-for-role \
    --profile "${PROFILE}" \
    --role-name "${ROLE_NAME}" \
    --query 'InstanceProfiles[0].InstanceProfileName' \
    --output text 2>/dev/null || true)"
  if [[ -n "${INSTANCE_PROFILE_NAME}" && "${INSTANCE_PROFILE_NAME}" != "None" ]]; then
    INSTANCE_PROFILE_ARN="$(aws iam get-instance-profile \
      --profile "${PROFILE}" \
      --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
      --query 'InstanceProfile.Arn' \
      --output text 2>/dev/null || true)"
  fi
fi

need_profile="false"
if [[ -z "${INSTANCE_PROFILE_ARN}" && -z "${INSTANCE_PROFILE_NAME}" ]]; then
  need_profile="true"
fi

if [[ -z "${SUBNET_ID}" || -z "${SECURITY_GROUP_ID}" || "${need_profile}" == "true" ]]; then
  token="$(imds_token)"
  if [[ -n "${token}" ]]; then
    macs="$(imds_get meta-data/network/interfaces/macs/ "${token}" || true)"
    mac="$(printf '%s\n' "${macs}" | head -n 1 | tr -d '/\r\n ' )"
    if [[ -n "${mac}" ]]; then
      if [[ -z "${SUBNET_ID}" ]]; then
        SUBNET_ID="$(imds_get "meta-data/network/interfaces/macs/${mac}/subnet-id" "${token}" | tr -d '\r\n ' || true)"
      fi
      if [[ -z "${SECURITY_GROUP_ID}" ]]; then
        SECURITY_GROUP_ID="$(imds_get "meta-data/network/interfaces/macs/${mac}/security-group-ids" "${token}" | head -n 1 | tr -d '\r\n ' || true)"
      fi
    fi
    if [[ "${need_profile}" == "true" ]]; then
      iam_info="$(imds_get meta-data/iam/info "${token}" || true)"
      INSTANCE_PROFILE_ARN="$(python3 -c 'import json,sys\ntry:\n  d=json.load(sys.stdin)\nexcept Exception:\n  raise SystemExit(0)\nprint((d.get(\"InstanceProfileArn\") or \"\").strip())' <<<"${iam_info}" 2>/dev/null || true)"
    fi
    if [[ "${need_profile}" == "true" && -z "${INSTANCE_PROFILE_ARN}" ]]; then
      # Some hardened runner images block /latest/meta-data/iam/info but still allow
      # instance credentials; fall back to EC2 DescribeInstances for self.
      self_id="$(imds_get meta-data/instance-id "${token}" | tr -d '\r\n ' || true)"
      if [[ -n "${self_id}" ]]; then
        INSTANCE_PROFILE_ARN="$(awsj ec2 describe-instances \
          --instance-ids "${self_id}" \
          --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \
          --output text 2>/dev/null | tr -d '\r\n ' || true)"
        if [[ "${INSTANCE_PROFILE_ARN}" == "None" ]]; then
          INSTANCE_PROFILE_ARN=""
        fi
      fi
    fi
    if [[ "${need_profile}" == "true" && -z "${INSTANCE_PROFILE_ARN}" ]]; then
      role_name="$(imds_get meta-data/iam/security-credentials/ "${token}" | head -n 1 | tr -d '\r\n ' || true)"
      if [[ -n "${role_name}" ]]; then
        INSTANCE_PROFILE_NAME="$(aws iam list-instance-profiles-for-role \
          --profile "${PROFILE}" \
          --role-name "${role_name}" \
          --query 'InstanceProfiles[0].InstanceProfileName' \
          --output text 2>/dev/null || true)"
        if [[ -n "${INSTANCE_PROFILE_NAME}" && "${INSTANCE_PROFILE_NAME}" != "None" ]]; then
          INSTANCE_PROFILE_ARN="$(aws iam get-instance-profile \
            --profile "${PROFILE}" \
            --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
            --query 'InstanceProfile.Arn' \
            --output text 2>/dev/null || true)"
        else
        INSTANCE_PROFILE_NAME="${role_name}"
        if [[ "${INSTANCE_PROFILE_NAME}" == *"InstanceRole"* ]]; then
          INSTANCE_PROFILE_NAME="${INSTANCE_PROFILE_NAME/InstanceRole/InstanceProfile}"
        elif [[ "${INSTANCE_PROFILE_NAME}" == *"Role"* ]]; then
          INSTANCE_PROFILE_NAME="${INSTANCE_PROFILE_NAME/Role/Profile}"
        fi
        fi
      fi
    fi
  fi
fi

if [[ -z "${SUBNET_ID}" || -z "${SECURITY_GROUP_ID}" || ( -z "${INSTANCE_PROFILE_ARN}" && -z "${INSTANCE_PROFILE_NAME}" ) ]]; then
  echo "failed to determine subnet/security-group/instance-profile for launch" >&2
  echo "subnet_id=${SUBNET_ID:-}" >&2
  echo "security_group_id=${SECURITY_GROUP_ID:-}" >&2
  echo "instance_profile_arn=${INSTANCE_PROFILE_ARN:-}" >&2
  echo "instance_profile_name=${INSTANCE_PROFILE_NAME:-}" >&2
  echo "stack_name=${STACK_NAME}" >&2
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
instance_profile_arg=""
if [[ -n "${INSTANCE_PROFILE_ARN}" ]]; then
  instance_profile_arg="Arn=${INSTANCE_PROFILE_ARN}"
else
  instance_profile_arg="Name=${INSTANCE_PROFILE_NAME}"
fi
launch_instance() {
  awsj ec2 run-instances \
    --image-id "${AMI_ID}" \
    --instance-type "${INSTANCE_TYPE}" \
    --subnet-id "${SUBNET_ID}" \
    --security-group-ids "${SECURITY_GROUP_ID}" \
    --iam-instance-profile "${instance_profile_arg}" \
    $(if [[ "${CRP_MODE}" == "v2" ]]; then printf '%s' "--enclave-options Enabled=true"; fi) \
    --block-device-mappings '[
      {
        "DeviceName": "/dev/sda1",
        "Ebs": { "VolumeSize": 200, "VolumeType": "gp3", "DeleteOnTermination": true }
      },
      {
        "DeviceName": "/dev/sdb",
        "Ebs": { "VolumeSize": 300, "VolumeType": "gp3", "DeleteOnTermination": true }
      }
    ]' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=juno-intents-e2e-devnet-testnet},{Key=juno-intents,Value=e2e-devnet-testnet}]' \
    --query 'Instances[0].InstanceId' \
    --output text
}

INSTANCE_ID=""
launch_attempt=0
while [[ -z "${INSTANCE_ID}" && "${launch_attempt}" -lt 10 ]]; do
  launch_attempt="$((launch_attempt + 1))"
  set +e
  launch_out="$(launch_instance 2>&1)"
  launch_ec="$?"
  set -e
  if [[ "${launch_ec}" -eq 0 ]]; then
    INSTANCE_ID="$(printf '%s' "${launch_out}" | tr -d '\r\n ' )"
    break
  fi
  if printf '%s' "${launch_out}" | grep -q "VcpuLimitExceeded"; then
    backoff="$((launch_attempt * 30))"
    if [[ "${backoff}" -gt 300 ]]; then backoff=300; fi
    echo "run-instances failed with VcpuLimitExceeded (attempt ${launch_attempt}/10); retrying in ${backoff}s..." >&2
    sleep "${backoff}"
    continue
  fi
  echo "run-instances failed (attempt ${launch_attempt}/10):" >&2
  printf '%s\n' "${launch_out}" >&2
  exit 1
done
if [[ -z "${INSTANCE_ID}" ]]; then
  echo "run-instances failed after ${launch_attempt} attempts" >&2
  exit 1
fi

echo "instance: ${INSTANCE_ID}" >&2
echo "waiting for instance status ok..." >&2
awsj ec2 wait instance-status-ok --instance-ids "${INSTANCE_ID}"

SSM_OUTPUT_BUCKET="${JUNO_E2E_SSM_OUTPUT_S3_BUCKET:-}"
SSM_OUTPUT_PREFIX="${JUNO_E2E_SSM_OUTPUT_S3_PREFIX:-}"
if [[ -z "${SSM_OUTPUT_BUCKET}" ]]; then
  SSM_OUTPUT_BUCKET="$(get_cf_output RunsOnBucketCache)"
  if [[ "${SSM_OUTPUT_BUCKET}" == "None" ]]; then
    SSM_OUTPUT_BUCKET=""
  fi
fi
if [[ -z "${SSM_OUTPUT_PREFIX}" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  # NB: runs-on instance role is scoped to bucket + cache/*.
  SSM_OUTPUT_PREFIX="cache/ssm/juno-intents/e2e-devnet-testnet/${ts}"
fi
export JUNO_E2E_SSM_OUTPUT_S3_BUCKET="${SSM_OUTPUT_BUCKET}"
export JUNO_E2E_SSM_OUTPUT_S3_PREFIX="${SSM_OUTPUT_PREFIX}"

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
export REGION INSTANCE_ID RUST_TOOLCHAIN RISC0_RUST_TOOLCHAIN RZUP_VERSION RISC0_GROTH16_VERSION SOLANA_CLI_VERSION GO_VERSION GIT_SHA DEPLOYMENT_NAME CRP_MODE PRIORITY_LEVEL RUN_MODE

ssm_timeout_seconds="${JUNO_E2E_SSM_TIMEOUT_SECONDS:-10200}" # 170 minutes
export JUNO_E2E_SSM_TIMEOUT_SECONDS="${ssm_timeout_seconds}"

COMMAND_ID="$(
  python3 - <<'PY'
import json
import os
import subprocess
import base64

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
deployment = os.environ["DEPLOYMENT_NAME"]
git_sha = os.environ["GIT_SHA"]
crp_mode = os.environ.get("CRP_MODE", "v1").strip()
priority_level = os.environ.get("PRIORITY_LEVEL", "Medium").strip()
run_mode = os.environ.get("RUN_MODE", "e2e").strip()
if run_mode not in ("e2e", "preflight"):
    raise SystemExit(f"RUN_MODE must be e2e or preflight (got: {run_mode})")

rust_toolchain = os.environ["RUST_TOOLCHAIN"]
risc0_rust_toolchain = os.environ["RISC0_RUST_TOOLCHAIN"]
rzup_version = os.environ["RZUP_VERSION"]
risc0_groth16_version = os.environ["RISC0_GROTH16_VERSION"]
solana_cli_version = os.environ.get("SOLANA_CLI_VERSION", "3.1.6").strip()
go_version = os.environ.get("GO_VERSION", "1.22.6")
timeout_seconds = int(os.environ.get("JUNO_E2E_SSM_TIMEOUT_SECONDS", "10200").strip() or "10200")
output_bucket = os.environ.get("JUNO_E2E_SSM_OUTPUT_S3_BUCKET", "").strip()
output_prefix = os.environ.get("JUNO_E2E_SSM_OUTPUT_S3_PREFIX", "").strip()
solver_keypair_json = os.environ.get("JUNO_E2E_SOLVER_KEYPAIR_JSON", "").strip()
creator_keypair_json = os.environ.get("JUNO_E2E_CREATOR_KEYPAIR_JSON", "").strip()
junocash_testnet_wif = os.environ.get("JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF", "").strip()

cmds = [
    "set -e",
    "export HOME=/root",
    "mkdir -p /root",
    "if ! command -v python3 >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends python3; fi",
    "if ! command -v git >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends git; fi",
    "if ! command -v curl >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends curl; fi",
    "rm -rf /root/juno-intents && git clone https://github.com/Abdullah1738/juno-intents.git /root/juno-intents",
    "cd /root/juno-intents",
    f"git checkout {git_sha}",
    "git rev-parse HEAD",
    "if ! command -v protoc >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends protobuf-compiler; fi",
    "if ! command -v docker >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends docker.io; fi",
    "if ! command -v growpart >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends cloud-guest-utils; fi",
    (
        'root_part="$(lsblk -pnro NAME,MOUNTPOINT | awk \'$2=="/"{print $1; exit}\')"; '
        'if [ -z "$root_part" ]; then root_part="$(findmnt -n -o SOURCE / || true)"; fi; '
        'root_part="$(readlink -f "$root_part" 2>/dev/null || echo "$root_part")"; '
        'fstype="$(findmnt -n -o FSTYPE / || true)"; '
        'if [ -b "$root_part" ] && command -v lsblk >/dev/null && command -v growpart >/dev/null; then '
        'disk="/dev/$(lsblk -no PKNAME "$root_part" 2>/dev/null | head -n 1)"; '
        'partnum="$(lsblk -no PARTNUM "$root_part" 2>/dev/null | head -n 1)"; '
        'if [ -z "$partnum" ]; then partnum="$(printf "%s" "$root_part" | sed -nE \'s/.*[^0-9]([0-9]+)$/\\1/p\')"; fi; '
        'if [ -n "$disk" ] && [ -n "$partnum" ]; then sudo growpart "$disk" "$partnum" || true; fi; '
        'case "$fstype" in '
        'ext4) sudo resize2fs "$root_part" || true ;; '
        'xfs) sudo xfs_growfs / || true ;; '
        'esac; '
        'fi; '
        'lsblk -o NAME,SIZE,TYPE,MOUNTPOINT | head -n 50; '
        'df -h /'
    ),
    "sudo systemctl stop docker docker.socket || sudo service docker stop || true",
    "sudo mkdir -p /opt/docker-data /etc/docker /var/lib",
    (
        'root_part="$(findmnt -n -o SOURCE / || true)"; '
        'root_disk=""; '
        'if [ -n "$root_part" ] && command -v lsblk >/dev/null; then '
        'root_disk="/dev/$(lsblk -no PKNAME "$root_part" 2>/dev/null | head -n 1)"; '
        'fi; '
        'docker_disk=""; '
        'if command -v lsblk >/dev/null; then '
        'for name in $(lsblk -d -n -o NAME,MODEL | awk \'$2=="Amazon" && $3=="Elastic" && $4=="Block" && $5=="Store" {print $1}\'); do '
        'dev="/dev/$name"; '
        'if [ -n "$root_disk" ] && [ "$dev" = "$root_disk" ]; then continue; fi; '
        'cnt="$(lsblk -n -o NAME "$dev" 2>/dev/null | wc -l | tr -d " ")"; '
        'if [ "$cnt" = "1" ]; then docker_disk="$dev"; break; fi; '
        'done; '
        'fi; '
        'if [ -n "$docker_disk" ]; then '
        'echo "formatting docker volume: $docker_disk" >&2; '
        'sudo mkfs.ext4 -F "$docker_disk"; '
        'sudo mount "$docker_disk" /opt/docker-data; '
        'fi; '
        'df -h /opt/docker-data || true; '
        'lsblk -d -o NAME,SIZE,MODEL | head -n 20'
    ),
    (
        "sudo python3 - <<'PY'\n"
        "import json\n"
        "import os\n"
        "path='/etc/docker/daemon.json'\n"
        "cfg={}\n"
        "try:\n"
        "  with open(path,'r',encoding='utf-8') as f:\n"
        "    cfg=json.load(f)\n"
        "except FileNotFoundError:\n"
        "  cfg={}\n"
        "except Exception:\n"
        "  cfg={}\n"
        "cfg['data-root']='/opt/docker-data'\n"
        "tmp=path+'.tmp'\n"
        "with open(tmp,'w',encoding='utf-8') as f:\n"
        "  json.dump(cfg,f,separators=(',',':'))\n"
        "  f.write('\\n')\n"
        "os.replace(tmp,path)\n"
        "PY"
    ),
    "sudo umount /var/lib/docker >/dev/null 2>&1 || true",
    "sudo rm -rf /var/lib/docker",
    "sudo mkdir -p /var/lib/docker",
    "sudo mount --bind /opt/docker-data /var/lib/docker",
    "sudo systemctl start docker || sudo service docker start || true",
    "docker info | grep -F 'Docker Root Dir' || true",
    "docker ps >/dev/null",
    f"if ! command -v go >/dev/null || ! go version | grep -q 'go{go_version}'; then curl -sSfL --retry 8 --retry-delay 5 --retry-all-errors https://go.dev/dl/go{go_version}.linux-amd64.tar.gz -o /tmp/go.tgz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz; fi",
    'export PATH="/usr/local/go/bin:$HOME/.cargo/bin:$HOME/.local/share/solana/solana-release/bin:$PATH"',
    "go version",
]

if run_mode == "e2e":
    cmds += [
        "if ! command -v cargo >/dev/null; then curl -sSfL --retry 8 --retry-delay 5 --retry-all-errors https://sh.rustup.rs | sh -s -- -y; fi",
        'export PATH="$HOME/.cargo/bin:/usr/local/go/bin:$HOME/.local/share/solana/solana-release/bin:$PATH"',
        f"rustup toolchain install {rust_toolchain} || true",
        f"rustup default {rust_toolchain} || true",
        f"rustup toolchain install {risc0_rust_toolchain} || true",
        f"if ! command -v rzup >/dev/null || ! rzup --version | grep -q '{rzup_version}'; then cargo install rzup --version {rzup_version} --locked --force; fi",
        f"rzup install rust {risc0_rust_toolchain}",
        f"rzup install risc0-groth16 {risc0_groth16_version}",
    ]

cmds += [
    "if ! command -v bzip2 >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends bzip2; fi",
    (
        'SOLANA_DIR="$HOME/.local/share/solana/solana-release"; '
        'if [ ! -x "${SOLANA_DIR}/bin/solana" ]; then '
        'rm -rf "${SOLANA_DIR}"; '
        'mkdir -p "$HOME/.local/share/solana"; '
        'curl -sSfL --retry 8 --retry-delay 5 --retry-all-errors '
        f'"https://github.com/anza-xyz/agave/releases/download/v{solana_cli_version}/solana-release-x86_64-unknown-linux-gnu.tar.bz2" '
        '-o /tmp/solana-release.tar.bz2; '
        'tar -xjf /tmp/solana-release.tar.bz2 -C "$HOME/.local/share/solana"; '
        'fi'
    ),
    'export PATH="$HOME/.local/share/solana/solana-release/bin:$PATH"',
    "solana --version",
    "spl-token --version",
]

if solver_keypair_json:
    solver_b64 = base64.b64encode(solver_keypair_json.encode("utf-8")).decode("ascii")
    cmds += [
        "mkdir -p /root/juno-secrets",
        "chmod 700 /root/juno-secrets",
        f"printf '%s' '{solver_b64}' | base64 -d > /root/juno-secrets/solver.json",
        "chmod 600 /root/juno-secrets/solver.json",
        "export JUNO_E2E_SOLVER_KEYPAIR=/root/juno-secrets/solver.json",
    ]

if creator_keypair_json:
    creator_b64 = base64.b64encode(creator_keypair_json.encode("utf-8")).decode("ascii")
    cmds += [
        "mkdir -p /root/juno-secrets",
        "chmod 700 /root/juno-secrets",
        f"printf '%s' '{creator_b64}' | base64 -d > /root/juno-secrets/creator.json",
        "chmod 600 /root/juno-secrets/creator.json",
        "export JUNO_E2E_CREATOR_KEYPAIR=/root/juno-secrets/creator.json",
    ]

if junocash_testnet_wif:
    wif_b64 = base64.b64encode(junocash_testnet_wif.encode("utf-8")).decode("ascii")
    cmds += [
        "mkdir -p /root/juno-secrets",
        "chmod 700 /root/juno-secrets",
        f"printf '%s' '{wif_b64}' | base64 -d > /root/juno-secrets/junocash-testnet-wif",
        "chmod 600 /root/juno-secrets/junocash-testnet-wif",
    ]

run_script = "./scripts/e2e/devnet-testnet-tee.sh"
if run_mode == "preflight":
    run_script = "./scripts/e2e/tee-preflight.sh"

cmds += [
    f"export JUNO_E2E_PRIORITY_LEVEL={priority_level}",
    (
        "if [ \"{mode}\" = \"v2\" ]; then "
        "set -e; "
        "if [ \"{run_mode}\" = \"e2e\" ]; then "
        "export PATH=/usr/local/cuda/bin:/usr/local/cuda-*/bin:$PATH; "
        "if ! command -v nvcc >/dev/null 2>&1; then "
        "sudo apt-get update; "
        "sudo apt-get install -y --no-install-recommends cuda-toolkit-12-4; "
        "export PATH=/usr/local/cuda/bin:/usr/local/cuda-*/bin:$PATH; "
        "fi; "
        "if ! command -v nvcc >/dev/null 2>&1; then echo 'nvcc not found (CUDA toolkit install incomplete)' >&2; exit 1; fi; "
        "fi; "
        "if ! command -v nitro-cli >/dev/null; then "
        "sudo apt-get update; "
        "sudo apt-get install -y --no-install-recommends clang gcc git libclang-dev libssl-dev llvm-dev make pkg-config; "
        "log=/tmp/nitro-cli-build.log; "
        "attempt=0; "
        "while [ $attempt -lt 3 ]; do "
        "attempt=$((attempt+1)); "
        "echo \"nitro-cli build attempt $attempt\" >&2; "
        "rm -f \"$log\"; "
        ": > \"$log\"; "
        "rm -rf /tmp/aws-nitro-enclaves-cli; "
        "if git clone --depth 1 --branch v1.4.4 https://github.com/aws/aws-nitro-enclaves-cli.git /tmp/aws-nitro-enclaves-cli >>\"$log\" 2>&1 "
        "&& make -C /tmp/aws-nitro-enclaves-cli nitro-cli >>\"$log\" 2>&1 "
        "&& make -C /tmp/aws-nitro-enclaves-cli vsock-proxy >>\"$log\" 2>&1 "
        "&& sudo env NITRO_CLI_INSTALL_DIR=/ make -C /tmp/aws-nitro-enclaves-cli install >>\"$log\" 2>&1; "
        "then break; fi; "
        "echo 'nitro-cli build/install failed (tailing log)' >&2; "
        "tail -n 80 \"$log\" >&2 || true; "
        "sleep $((attempt*10)); "
        "done; "
        "export PATH=/usr/bin:$PATH; "
        "export NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs/; "
        "if ! command -v nitro-cli >/dev/null; then echo 'nitro-cli install failed' >&2; exit 1; fi; "
        "fi; "
        "if command -v depmod >/dev/null; then sudo depmod -a || true; fi; "
        "sudo modprobe nitro_enclaves || true; "
        "if [ -f /etc/nitro_enclaves/allocator.yaml ]; then "
        "sudo sed -i -E 's/^memory_mib:.*$/memory_mib: 4096/' /etc/nitro_enclaves/allocator.yaml || true; "
        "sudo sed -i -E 's/^cpu_count:.*$/cpu_count: 4/' /etc/nitro_enclaves/allocator.yaml || true; "
        "fi; "
        "sudo systemctl daemon-reload >/dev/null 2>&1 || true; "
        "sudo systemctl enable nitro-enclaves-allocator.service >/dev/null 2>&1 || true; "
        "sudo systemctl restart nitro-enclaves-allocator.service >/dev/null 2>&1 || sudo systemctl start nitro-enclaves-allocator.service >/dev/null 2>&1 || true; "
        "if command -v systemctl >/dev/null 2>&1; then "
        "if ! systemctl is-active nitro-enclaves-allocator.service >/dev/null 2>&1; then "
        "echo 'nitro-enclaves-allocator.service is not active' >&2; "
        "systemctl status nitro-enclaves-allocator.service --no-pager >&2 || true; "
        "journalctl -u nitro-enclaves-allocator.service -n 200 --no-pager >&2 || true; "
        "exit 1; "
        "fi; "
        "fi; "
        "if [ -f /sys/module/nitro_enclaves/parameters/ne_cpus ]; then echo \"ne_cpus=$(cat /sys/module/nitro_enclaves/parameters/ne_cpus)\" >&2; fi; "
        "grep -E '^(HugePages_Total|HugePages_Free|Hugepagesize):' /proc/meminfo >&2 || true; "
        "if [ ! -e /dev/nitro_enclaves ]; then echo \"/dev/nitro_enclaves missing\" >&2; exit 1; fi; "
        "mkdir -p /var/log/juno-e2e; "
        "rm -f /var/log/juno-e2e/e2e.pid /var/log/juno-e2e/e2e.exit; "
        "nohup bash -lc 'cd /root/juno-intents && JUNO_E2E_JUNOCASH_TESTNET_TADDR_WIF=\"$(cat /root/juno-secrets/junocash-testnet-wif 2>/dev/null || true)\" JUNO_E2E_ARTIFACT_DIR=/var/log/juno-e2e {run_script} --base-deployment {deployment}; ec=$?; echo $ec > /var/log/juno-e2e/e2e.exit' "
        ">/var/log/juno-e2e/e2e.log 2>&1 & "
        "echo $! > /var/log/juno-e2e/e2e.pid; "
        "echo \"e2e_pid=$(cat /var/log/juno-e2e/e2e.pid)\" >&2; "
        "else "
        "./scripts/e2e/devnet-testnet.sh --deployment {deployment}; "
        "fi"
    ).format(mode=crp_mode, deployment=deployment, run_mode=run_mode, run_script=run_script),
]

payload = json.dumps({"commands": cmds})
args = [
    "aws",
    "--profile",
    "juno",
    "--region",
    region,
    "ssm",
    "send-command",
    "--timeout-seconds",
    str(timeout_seconds),
]
if output_bucket:
    args += ["--output-s3-bucket-name", output_bucket]
    if output_prefix:
        args += ["--output-s3-key-prefix", output_prefix]
out = subprocess.check_output(
    args
    + [
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
if [[ -n "${SSM_OUTPUT_BUCKET}" ]]; then
  echo "ssm output s3: s3://${SSM_OUTPUT_BUCKET}/${SSM_OUTPUT_PREFIX}/${COMMAND_ID}/${INSTANCE_ID}/" >&2
fi
echo "waiting for command to finish..." >&2
start_ts="$(date +%s)"
status=""
last_status=""
while true; do
  status="$(awsj ssm get-command-invocation \
    --command-id "${COMMAND_ID}" \
    --instance-id "${INSTANCE_ID}" \
    --query 'Status' \
    --output text 2>/dev/null || true)"
  if [[ -z "${status}" || "${status}" == "None" ]]; then
    sleep 5
    continue
  fi
  if [[ "${status}" != "${last_status}" ]]; then
    echo "ssm status: ${status}" >&2
    last_status="${status}"
  fi
  case "${status}" in
    Success|Failed|Cancelled|TimedOut)
      break
      ;;
    Pending|InProgress|Delayed)
      ;;
    *)
      echo "unexpected ssm status: ${status}" >&2
      ;;
  esac
  now_ts="$(date +%s)"
  if (( now_ts - start_ts > ssm_timeout_seconds )); then
    echo "ssm command did not finish within ${ssm_timeout_seconds}s (timing out)" >&2
    status="TimedOut"
    break
  fi
  sleep 15
done

download_ssm_output() {
  local cmd_id="${1:-${COMMAND_ID}}"
  if [[ -z "${SSM_OUTPUT_BUCKET:-}" || -z "${SSM_OUTPUT_PREFIX:-}" || -z "${cmd_id}" ]]; then
    return 0
  fi
  local uri="s3://${SSM_OUTPUT_BUCKET}/${SSM_OUTPUT_PREFIX}/${cmd_id}/${INSTANCE_ID}/"
  local out_dir="${LOCAL_OUT_DIR}/ssm/${INSTANCE_ID}/${cmd_id}"
  mkdir -p "${out_dir}"
  echo "downloading ssm output to ${out_dir}..." >&2
  echo "ssm output uri: ${uri}" >&2
  for i in $(seq 1 12); do
    if awsj s3 ls "${uri}" --recursive >/dev/null 2>&1; then
      awsj s3 cp "${uri}" "${out_dir}/" --recursive >/dev/null || true
      return 0
    fi
    sleep "$((i * 5))"
  done
  echo "ssm output not found in s3 (yet): ${uri}" >&2
  return 1
}

ssm_send_script() {
  local timeout_seconds="${1:-600}"
  local payload
  payload="$(python3 -c 'import json,sys
cmds=[]
for ln in sys.stdin.read().splitlines():
  ln=ln.rstrip("\n")
  if not ln.strip():
    continue
  cmds.append(ln)
if not cmds:
  cmds=["true"]
print(json.dumps({"commands": cmds}))'
)"

  local args=(ssm send-command --timeout-seconds "${timeout_seconds}")
  if [[ -n "${SSM_OUTPUT_BUCKET:-}" ]]; then
    args+=(--output-s3-bucket-name "${SSM_OUTPUT_BUCKET}")
    if [[ -n "${SSM_OUTPUT_PREFIX:-}" ]]; then
      args+=(--output-s3-key-prefix "${SSM_OUTPUT_PREFIX}")
    fi
  fi
  args+=(
    --document-name AWS-RunShellScript
    --targets "Key=InstanceIds,Values=${INSTANCE_ID}"
    --parameters "${payload}"
    --query "Command.CommandId"
    --output text
  )
  awsj "${args[@]}"
}

ssm_wait() {
  local cmd_id="$1"
  local timeout_seconds="${2:-600}"
  local start_ts now_ts status last_status
  start_ts="$(date +%s)"
  status=""
  last_status=""
  while true; do
    status="$(awsj ssm get-command-invocation \
      --command-id "${cmd_id}" \
      --instance-id "${INSTANCE_ID}" \
      --query 'Status' \
      --output text 2>/dev/null || true)"
    if [[ -z "${status}" || "${status}" == "None" ]]; then
      sleep 2
      continue
    fi
    if [[ "${status}" != "${last_status}" ]]; then
      echo "ssm cmd ${cmd_id} status: ${status}" >&2
      last_status="${status}"
    fi
    case "${status}" in
      Success|Failed|Cancelled|TimedOut)
        echo "${status}"
        return 0
        ;;
      Pending|InProgress|Delayed)
        ;;
      *)
        echo "unexpected ssm status for ${cmd_id}: ${status}" >&2
        ;;
    esac
    now_ts="$(date +%s)"
    if (( now_ts - start_ts > timeout_seconds )); then
      echo "TimedOut"
      return 0
    fi
    sleep 5
  done
}

ssm_stdout() {
  local cmd_id="$1"
  awsj ssm get-command-invocation \
    --command-id "${cmd_id}" \
    --instance-id "${INSTANCE_ID}" \
    --query 'StandardOutputContent' \
    --output text 2>/dev/null || true
}

ssm_stderr() {
  local cmd_id="$1"
  awsj ssm get-command-invocation \
    --command-id "${cmd_id}" \
    --instance-id "${INSTANCE_ID}" \
    --query 'StandardErrorContent' \
    --output text 2>/dev/null || true
}

download_ssm_output "${COMMAND_ID}" || true

if [[ "${status}" != "Success" ]]; then
  awsj ssm get-command-invocation \
    --command-id "${COMMAND_ID}" \
    --instance-id "${INSTANCE_ID}" \
    --query '{Status:Status,Stdout:StandardOutputContent,Stderr:StandardErrorContent}' \
    --output json >&2 || true
  exit 1
fi

echo "initial ssm stdout (tail):" >&2
ssm_stdout "${COMMAND_ID}" | tail -n 80 >&2 || true
echo "initial ssm stderr (tail):" >&2
ssm_stderr "${COMMAND_ID}" | tail -n 80 >&2 || true

if [[ "${CRP_MODE}" == "v2" ]]; then
  echo "waiting for background e2e (v2)..." >&2

  if [[ "${RUN_MODE}" == "preflight" ]]; then
    remote_timeout_seconds="${JUNO_E2E_REMOTE_TIMEOUT_SECONDS:-3600}" # 1h
    poll_interval_seconds="${JUNO_E2E_REMOTE_POLL_INTERVAL_SECONDS:-20}"
  else
    remote_timeout_seconds="${JUNO_E2E_REMOTE_TIMEOUT_SECONDS:-14400}" # 4h
    poll_interval_seconds="${JUNO_E2E_REMOTE_POLL_INTERVAL_SECONDS:-60}"
  fi

  e2e_status=""
  e2e_exit_code=""
  start_ts="$(date +%s)"
  while true; do
    check_id="$(
      ssm_send_script 600 <<'EOF'
	set -eu
d=/var/log/juno-e2e
if [ -f "$d/e2e.exit" ]; then
  echo "status=done"
  echo "exit_code=$(tr -d '\r\n ' < "$d/e2e.exit")"
  exit 0
fi
if [ -f "$d/e2e.pid" ]; then
  pid="$(tr -d '\r\n ' < "$d/e2e.pid" || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "status=running"
    echo "pid=${pid}"
    exit 0
  fi
  echo "status=stopped"
  echo "pid=${pid}"
  exit 0
fi
echo "status=notstarted"
EOF
    )"
    check_status="$(ssm_wait "${check_id}" 300)"
    download_ssm_output "${check_id}" || true

    if [[ "${check_status}" != "Success" ]]; then
      echo "SSM e2e status check failed (status=${check_status})" >&2
      ssm_stdout "${check_id}" >&2 || true
      ssm_stderr "${check_id}" >&2 || true
      exit 1
    fi

    check_out="$(ssm_stdout "${check_id}")"
    e2e_status="$(printf '%s\n' "${check_out}" | sed -nE 's/^status=(.+)$/\1/p' | tail -n 1)"
    e2e_exit_code="$(printf '%s\n' "${check_out}" | sed -nE 's/^exit_code=([0-9]+)$/\1/p' | tail -n 1)"

    if [[ "${e2e_status}" == "done" ]]; then
      break
    fi
    if [[ "${e2e_status}" == "stopped" ]]; then
      echo "e2e process stopped before writing exit code" >&2
      break
    fi

    now_ts="$(date +%s)"
    if (( now_ts - start_ts > remote_timeout_seconds )); then
      echo "remote e2e timed out after ${remote_timeout_seconds}s" >&2
      break
    fi
    echo "e2e status: ${e2e_status:-unknown} (elapsed=$((now_ts-start_ts))s)" >&2
    sleep "${poll_interval_seconds}"
  done

  tail_id="$(
    ssm_send_script 600 <<'EOF'
	set -eu
d=/var/log/juno-e2e
echo "---- e2e.log (tail) ----"
tail -n 200 "$d/e2e.log" || true
if [ -f "$d/e2e.exit" ]; then
  echo "exit_code=$(tr -d '\r\n ' < "$d/e2e.exit")"
fi
EOF
  )"
  tail_status="$(ssm_wait "${tail_id}" 300)"
  download_ssm_output "${tail_id}" || true

  if [[ "${tail_status}" != "Success" ]]; then
    echo "SSM e2e tail failed (status=${tail_status})" >&2
    ssm_stdout "${tail_id}" >&2 || true
    ssm_stderr "${tail_id}" >&2 || true
  else
    echo "e2e tail:" >&2
    ssm_stdout "${tail_id}" >&2 || true
  fi

  fetch_remote_file() {
    local remote_path="$1"
    local local_path="$2"

    local cmd_id status out b64
    cmd_id="$(
      ssm_send_script 600 <<EOF
	set -eu
p="${remote_path}"
if [ ! -f "\$p" ]; then
  echo "missing=1"
  exit 0
fi
python3 - <<'PY'
import base64,sys
p="${remote_path}"
data=open(p,"rb").read()
print("missing=0")
print("b64="+base64.b64encode(data).decode("ascii"))
PY
EOF
    )"
    status="$(ssm_wait "${cmd_id}" 300)"
    download_ssm_output "${cmd_id}" || true

    if [[ "${status}" != "Success" ]]; then
      echo "failed to fetch ${remote_path} (ssm status=${status})" >&2
      ssm_stdout "${cmd_id}" >&2 || true
      ssm_stderr "${cmd_id}" >&2 || true
      return 1
    fi

    out="$(ssm_stdout "${cmd_id}" | tr -d '\r' || true)"
    if printf '%s\n' "${out}" | grep -q '^missing=1$'; then
      echo "remote file missing: ${remote_path}" >&2
      return 1
    fi

    b64="$(printf '%s\n' "${out}" | sed -nE 's/^b64=(.+)$/\1/p' | tail -n 1)"
    if [[ -z "${b64}" ]]; then
      echo "missing b64 payload for ${remote_path}" >&2
      printf '%s\n' "${out}" | tail -n 40 >&2 || true
      return 1
    fi

    mkdir -p "$(dirname "${local_path}")"
    if ! python3 - "${local_path}" "${b64}" <<'PY'
import base64,sys
path=sys.argv[1]
b64=sys.argv[2].strip()
data=base64.b64decode(b64.encode("ascii"), validate=True)
with open(path,"wb") as f:
  f.write(data)
PY
    then
      echo "failed to decode base64 payload for ${remote_path}" >&2
      return 1
    fi
    echo "downloaded ${remote_path} -> ${local_path}" >&2
    return 0
  }

  echo "downloading remote artifacts (best effort)..." >&2
  fetch_remote_file "/var/log/juno-e2e/deployment.json" "${LOCAL_OUT_DIR}/artifacts/${INSTANCE_ID}/deployment.json" || true
  fetch_remote_file "/var/log/juno-e2e/tee-summary.json" "${LOCAL_OUT_DIR}/artifacts/${INSTANCE_ID}/tee-summary.json" || true
  fetch_remote_file "/var/log/juno-e2e/e2e-summary.json" "${LOCAL_OUT_DIR}/artifacts/${INSTANCE_ID}/e2e-summary.json" || true
  fetch_remote_file "/var/log/juno-e2e/tee-preflight-summary.json" "${LOCAL_OUT_DIR}/artifacts/${INSTANCE_ID}/tee-preflight-summary.json" || true
  fetch_remote_file "/var/log/juno-e2e/crp-monitor-report.json" "${LOCAL_OUT_DIR}/artifacts/${INSTANCE_ID}/crp-monitor-report.json" || true

  if [[ "${e2e_status}" != "done" || "${e2e_exit_code}" != "0" ]]; then
    echo "e2e failed (status=${e2e_status:-unknown} exit_code=${e2e_exit_code:-unknown})" >&2
    exit 1
  fi

  echo "e2e succeeded" >&2
  exit 0
fi

echo "done" >&2
