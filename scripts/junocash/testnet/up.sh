#!/usr/bin/env bash
set -euo pipefail

NAME_A="${JUNO_TESTNET_CONTAINER_NAME_A:-juno-testnet-a}"
NAME_B="${JUNO_TESTNET_CONTAINER_NAME_B:-juno-testnet-b}"
DATA_DIR_A="${JUNO_TESTNET_DATA_DIR_A:-tmp/junocash-testnet-a}"
DATA_DIR_B="${JUNO_TESTNET_DATA_DIR_B:-tmp/junocash-testnet-b}"
IMAGE="${JUNO_TESTNET_BASE_IMAGE:-juno-intents/junocash-testnet:ubuntu22}"
NETWORK="${JUNO_TESTNET_NETWORK:-juno-testnet-net}"

JUNOCASH_ROOT="$(scripts/junocash/fetch-linux64.sh)"

mkdir -p "${DATA_DIR_A}" "${DATA_DIR_B}"

if docker ps --format '{{.Names}}' | grep -qx "${NAME_A}" && docker ps --format '{{.Names}}' | grep -qx "${NAME_B}"; then
  echo "${NAME_A} and ${NAME_B} already running" >&2
  exit 0
fi

docker rm -f "${NAME_A}" "${NAME_B}" >/dev/null 2>&1 || true

docker network inspect "${NETWORK}" >/dev/null 2>&1 || docker network create "${NETWORK}" >/dev/null

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_FLAG=()
if [[ "${JUNO_TESTNET_DOCKER_USER:-}" != "" ]]; then
  USER_FLAG=(--user "${JUNO_TESTNET_DOCKER_USER}")
elif command -v id >/dev/null; then
  USER_FLAG=(--user "$(id -u):$(id -g)")
fi

if [[ "${IMAGE}" == "juno-intents/junocash-testnet:ubuntu22" ]]; then
  build_log="tmp/junocash/testnet-docker-build.log"
  mkdir -p "$(dirname "${build_log}")"
  attempt=0
  while [[ "${attempt}" -lt 3 ]]; do
    attempt="$((attempt + 1))"
    if docker build -t "${IMAGE}" -f "${script_dir}/Dockerfile" "${script_dir}" >"${build_log}" 2>&1; then
      break
    fi
    echo "junocash testnet docker build failed (attempt ${attempt}/3)..." >&2
    tail -n 120 "${build_log}" >&2 || true
    sleep "$((attempt * 5))"
  done
  if [[ "${attempt}" -ge 3 ]]; then
    echo "junocash testnet docker build failed after ${attempt} attempts" >&2
    exit 1
  fi
fi

docker run -d \
  --name "${NAME_B}" \
  --network "${NETWORK}" \
  "${USER_FLAG[@]}" \
  -v "$(pwd)/${JUNOCASH_ROOT}:/opt/junocash:ro" \
  -v "$(pwd)/${DATA_DIR_B}:/data" \
  "${IMAGE}" \
  /opt/junocash/bin/junocashd \
    -testnet \
    -datadir=/data \
    -txindex=1 \
    -server=1 \
    -printtoconsole=1 \
    -rpcworkqueue=64 \
    -rpcclienttimeout=120 \
    -dnsseed=0 \
    -listen=1 \
    -bind=0.0.0.0 \
    -connect="${NAME_A}:18234" >/dev/null

docker run -d \
  --name "${NAME_A}" \
  --network "${NETWORK}" \
  "${USER_FLAG[@]}" \
  -v "$(pwd)/${JUNOCASH_ROOT}:/opt/junocash:ro" \
  -v "$(pwd)/${DATA_DIR_A}:/data" \
  "${IMAGE}" \
  /opt/junocash/bin/junocashd \
    -testnet \
    -datadir=/data \
    -txindex=1 \
    -server=1 \
    -printtoconsole=1 \
    -rpcworkqueue=64 \
    -rpcclienttimeout=120 \
    -dnsseed=0 \
    -listen=1 \
    -bind=0.0.0.0 \
    -connect="${NAME_B}:18234" >/dev/null

echo "waiting for testnet rpc..." >&2
for _ in $(seq 1 60); do
  if ! docker ps -a --format '{{.Names}}' | grep -qx "${NAME_A}"; then
    echo "testnet container missing: ${NAME_A}" >&2
    exit 1
  fi
  if ! docker ps -a --format '{{.Names}}' | grep -qx "${NAME_B}"; then
    echo "testnet container missing: ${NAME_B}" >&2
    exit 1
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "${NAME_A}"; then
    echo "testnet container exited early: ${NAME_A}" >&2
    docker logs "${NAME_A}" >&2 || true
    exit 1
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "${NAME_B}"; then
    echo "testnet container exited early: ${NAME_B}" >&2
    docker logs "${NAME_B}" >&2 || true
    exit 1
  fi
  if scripts/junocash/testnet/cli.sh getblockcount >/dev/null 2>&1; then
    echo "testnet ready" >&2
    exit 0
  fi
  sleep 1
done

docker logs --tail 200 "${NAME_A}" >&2 || true
docker logs --tail 200 "${NAME_B}" >&2 || true
echo "testnet rpc did not become ready" >&2
exit 1
