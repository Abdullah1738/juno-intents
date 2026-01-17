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
SOLANA_CLI_VERSION="${JUNO_SOLANA_CLI_VERSION:-${SOLANA_CLI_VERSION:-3.1.6}}"
GO_VERSION="${JUNO_GO_VERSION:-1.22.6}"

REF=""
DEPLOYMENT_NAME=""
CRP_MODE="${JUNO_E2E_CRP_MODE:-v1}"
PRIORITY_LEVEL="${JUNO_E2E_PRIORITY_LEVEL:-Medium}"

SUBNET_ID="${JUNO_E2E_SUBNET_ID:-}"
SECURITY_GROUP_ID="${JUNO_E2E_SECURITY_GROUP_ID:-}"
INSTANCE_PROFILE_ARN="${JUNO_E2E_INSTANCE_PROFILE_ARN:-}"
INSTANCE_PROFILE_NAME="${JUNO_E2E_INSTANCE_PROFILE_NAME:-}"

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/aws/e2e-devnet-testnet.sh --deployment <name> [--ref <git-ref>] [--crp-mode v1|v2] [--priority-level <level>]

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
INSTANCE_ID="$(awsj ec2 run-instances \
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
export REGION INSTANCE_ID RUST_TOOLCHAIN RISC0_RUST_TOOLCHAIN RZUP_VERSION RISC0_GROTH16_VERSION SOLANA_CLI_VERSION GO_VERSION GIT_SHA DEPLOYMENT_NAME CRP_MODE PRIORITY_LEVEL
COMMAND_ID="$(
  python3 - <<'PY'
import json
import os
import subprocess

region = os.environ["REGION"]
instance_id = os.environ["INSTANCE_ID"]
deployment = os.environ["DEPLOYMENT_NAME"]
git_sha = os.environ["GIT_SHA"]
crp_mode = os.environ.get("CRP_MODE", "v1").strip()
priority_level = os.environ.get("PRIORITY_LEVEL", "Medium").strip()

rust_toolchain = os.environ["RUST_TOOLCHAIN"]
risc0_rust_toolchain = os.environ["RISC0_RUST_TOOLCHAIN"]
rzup_version = os.environ["RZUP_VERSION"]
risc0_groth16_version = os.environ["RISC0_GROTH16_VERSION"]
solana_cli_version = os.environ.get("SOLANA_CLI_VERSION", "3.1.6").strip()
go_version = os.environ.get("GO_VERSION", "1.22.6")

cmds = [
    "set -e",
    "export HOME=/root",
    "if ! command -v python3 >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends python3; fi",
    "if ! command -v git >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends git; fi",
    "if ! command -v curl >/dev/null; then sudo apt-get update && sudo apt-get install -y --no-install-recommends curl; fi",
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
    "if ! command -v cargo >/dev/null; then curl -sSfL --retry 8 --retry-delay 5 --retry-all-errors https://sh.rustup.rs | sh -s -- -y; fi",
    'export PATH="$HOME/.cargo/bin:/usr/local/go/bin:$HOME/.local/share/solana/solana-release/bin:$PATH"',
    f"rustup toolchain install {rust_toolchain} || true",
    f"rustup default {rust_toolchain} || true",
    f"rustup toolchain install {risc0_rust_toolchain} || true",
    f"if ! command -v rzup >/dev/null || ! rzup --version | grep -q '{rzup_version}'; then cargo install rzup --version {rzup_version} --locked --force; fi",
    f"rzup install rust {risc0_rust_toolchain}",
    f"rzup install risc0-groth16 {risc0_groth16_version}",
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
    "rm -rf juno-intents && git clone https://github.com/Abdullah1738/juno-intents.git",
    "cd juno-intents",
    f"git checkout {git_sha}",
    f"export JUNO_E2E_PRIORITY_LEVEL={priority_level}",
    (
        "if [ \"{mode}\" = \"v2\" ]; then "
        "set -e; "
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
        "sudo sed -i -E 's/^cpu_count:.*$/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml || true; "
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
        "./scripts/e2e/devnet-testnet-tee.sh --base-deployment {deployment}; "
        "else "
        "./scripts/e2e/devnet-testnet.sh --deployment {deployment}; "
        "fi"
    ).format(mode=crp_mode, deployment=deployment),
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
ssm_timeout_seconds="${JUNO_E2E_SSM_TIMEOUT_SECONDS:-10200}" # 170 minutes
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
