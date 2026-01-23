#!/usr/bin/env bash
set -euo pipefail

NAME="${JUNO_REGTEST_CONTAINER_NAME:-juno-regtest}"
DATA_DIR="${JUNO_REGTEST_DATA_DIR:-tmp/junocash-regtest}"
IMAGE="${JUNO_REGTEST_BASE_IMAGE:-juno-intents/junocash-regtest:ubuntu22}"
DOCKER_PLATFORM="${JUNO_REGTEST_DOCKER_PLATFORM:-${JUNO_DOCKER_PLATFORM:-linux/amd64}}"

JUNOCASH_ROOT="$(scripts/junocash/fetch-linux64.sh)"

mkdir -p "${DATA_DIR}"

if docker ps --format '{{.Names}}' | grep -qx "${NAME}"; then
  echo "${NAME} already running" >&2
  exit 0
fi

docker rm -f "${NAME}" >/dev/null 2>&1 || true

DATA_DIR_HOST="${DATA_DIR}"
if [[ "${DATA_DIR_HOST}" != /* ]]; then
  DATA_DIR_HOST="$(pwd)/${DATA_DIR_HOST}"
fi

PLATFORM_FLAG=()
if [[ -n "${DOCKER_PLATFORM}" ]]; then
  PLATFORM_FLAG=(--platform "${DOCKER_PLATFORM}")
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_FLAG=()
if [[ "${JUNO_REGTEST_DOCKER_USER:-}" != "" ]]; then
  USER_FLAG=(--user "${JUNO_REGTEST_DOCKER_USER}")
elif command -v id >/dev/null; then
  USER_FLAG=(--user "$(id -u):$(id -g)")
fi

if [[ "${IMAGE}" == "juno-intents/junocash-regtest:ubuntu22" ]]; then
  docker build "${PLATFORM_FLAG[@]}" -t "${IMAGE}" -f "${script_dir}/Dockerfile" "${script_dir}" >/dev/null
fi

docker run -d \
  "${PLATFORM_FLAG[@]}" \
  --name "${NAME}" \
  "${USER_FLAG[@]}" \
  -v "$(pwd)/${JUNOCASH_ROOT}:/opt/junocash:ro" \
  -v "${DATA_DIR_HOST}:/data" \
  "${IMAGE}" \
  /opt/junocash/bin/junocashd \
    -regtest \
    -datadir=/data \
    -exportdir=/data \
    -txindex=1 \
    -server=1 \
    -printtoconsole=1 \
    -rpcworkqueue=64 \
    -rpcclienttimeout=120 >/dev/null

echo "waiting for regtest rpc..." >&2
for _ in $(seq 1 60); do
  if ! docker ps -a --format '{{.Names}}' | grep -qx "${NAME}"; then
    echo "regtest container missing: ${NAME}" >&2
    exit 1
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "${NAME}"; then
    echo "regtest container exited early: ${NAME}" >&2
    docker logs "${NAME}" >&2 || true
    exit 1
  fi
  if scripts/junocash/regtest/cli.sh getblockcount >/dev/null 2>&1; then
    echo "regtest ready" >&2
    exit 0
  fi
  sleep 1
done

docker logs "${NAME}" >&2 || true
echo "regtest rpc did not become ready" >&2
exit 1
