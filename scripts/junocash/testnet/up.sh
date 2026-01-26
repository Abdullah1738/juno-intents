#!/usr/bin/env bash
set -euo pipefail

NAME_A="${JUNO_TESTNET_CONTAINER_NAME_A:-juno-testnet-a}"
NAME_B="${JUNO_TESTNET_CONTAINER_NAME_B:-juno-testnet-b}"
DATA_DIR_A="${JUNO_TESTNET_DATA_DIR_A:-tmp/junocash-testnet-a}"
DATA_DIR_B="${JUNO_TESTNET_DATA_DIR_B:-tmp/junocash-testnet-b}"
IMAGE="${JUNO_TESTNET_BASE_IMAGE:-juno-intents/junocash-testnet:ubuntu22}"
NETWORK="${JUNO_TESTNET_NETWORK:-juno-testnet-net}"
DOCKER_PLATFORM="${JUNO_TESTNET_DOCKER_PLATFORM:-${JUNO_DOCKER_PLATFORM:-linux/amd64}}"
MODE="${JUNO_TESTNET_MODE:-public}"
IBD_SKIP_TX_VERIFICATION="${JUNO_TESTNET_IBD_SKIP_TX_VERIFICATION:-1}"
MAXCONNECTIONS="${JUNO_TESTNET_MAXCONNECTIONS:-}"
DBCACHE_MB="${JUNO_TESTNET_DBCACHE_MB:-}"
PAR="${JUNO_TESTNET_PAR:-}"
TXINDEX="${JUNO_TESTNET_TXINDEX:-1}"

JUNOCASH_ROOT="$(scripts/junocash/fetch-linux64.sh)"

mkdir -p "${DATA_DIR_A}" "${DATA_DIR_B}"

DATA_DIR_A_HOST="${DATA_DIR_A}"
if [[ "${DATA_DIR_A_HOST}" != /* ]]; then
  DATA_DIR_A_HOST="$(pwd)/${DATA_DIR_A_HOST}"
fi
DATA_DIR_B_HOST="${DATA_DIR_B}"
if [[ "${DATA_DIR_B_HOST}" != /* ]]; then
  DATA_DIR_B_HOST="$(pwd)/${DATA_DIR_B_HOST}"
fi

case "${MODE}" in
  public)
    if docker ps --format '{{.Names}}' | grep -qx "${NAME_A}"; then
      echo "${NAME_A} already running" >&2
      exit 0
    fi
    ;;
  pair)
    if docker ps --format '{{.Names}}' | grep -qx "${NAME_A}" && docker ps --format '{{.Names}}' | grep -qx "${NAME_B}"; then
      echo "${NAME_A} and ${NAME_B} already running" >&2
      exit 0
    fi
    ;;
  *)
    echo "unsupported JUNO_TESTNET_MODE: ${MODE} (expected: public|pair)" >&2
    exit 2
    ;;
esac

docker rm -f "${NAME_A}" "${NAME_B}" >/dev/null 2>&1 || true

docker network inspect "${NETWORK}" >/dev/null 2>&1 || docker network create "${NETWORK}" >/dev/null

PLATFORM_FLAG=()
if [[ -n "${DOCKER_PLATFORM}" ]]; then
  PLATFORM_FLAG=(--platform "${DOCKER_PLATFORM}")
fi

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
    if docker build "${PLATFORM_FLAG[@]}" -t "${IMAGE}" -f "${script_dir}/Dockerfile" "${script_dir}" >"${build_log}" 2>&1; then
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

IBD_FLAGS=()
if [[ "${IBD_SKIP_TX_VERIFICATION}" == "1" ]]; then
  IBD_FLAGS=(-ibdskiptxverification)
fi

PERF_FLAGS=()
if [[ -n "${MAXCONNECTIONS}" ]] && [[ "${MAXCONNECTIONS}" =~ ^[0-9]+$ ]] && [[ "${MAXCONNECTIONS}" -gt 0 ]]; then
  PERF_FLAGS+=(-maxconnections="${MAXCONNECTIONS}")
fi
if [[ -n "${DBCACHE_MB}" ]] && [[ "${DBCACHE_MB}" =~ ^[0-9]+$ ]] && [[ "${DBCACHE_MB}" -gt 0 ]]; then
  PERF_FLAGS+=(-dbcache="${DBCACHE_MB}")
fi
if [[ -n "${PAR}" ]] && [[ "${PAR}" =~ ^[0-9]+$ ]] && [[ "${PAR}" -ge 0 ]]; then
  PERF_FLAGS+=(-par="${PAR}")
fi

TXINDEX_FLAG=()
if [[ "${TXINDEX}" == "1" ]]; then
  TXINDEX_FLAG=(-txindex=1)
fi

BOOTSTRAP_NODES_CSV="${JUNO_TESTNET_BOOTSTRAP_NODES:-199.247.15.208:18234}"
BOOTSTRAP_FLAGS=()
if [[ -n "${BOOTSTRAP_NODES_CSV}" ]]; then
  IFS=',' read -r -a bootstrap_nodes <<<"${BOOTSTRAP_NODES_CSV}"
  for node in "${bootstrap_nodes[@]}"; do
    node="$(printf '%s' "${node}" | tr -d ' \t\r\n')"
    if [[ -n "${node}" ]]; then
      BOOTSTRAP_FLAGS+=(-addnode="${node}")
    fi
  done
fi

if [[ "${MODE}" == "public" ]]; then
  docker run -d \
    ${PLATFORM_FLAG[@]+"${PLATFORM_FLAG[@]}"} \
    --name "${NAME_A}" \
    ${USER_FLAG[@]+"${USER_FLAG[@]}"} \
    -v "$(pwd)/${JUNOCASH_ROOT}:/opt/junocash:ro" \
    -v "${DATA_DIR_A_HOST}:/data" \
    "${IMAGE}" \
    /opt/junocash/bin/junocashd \
      -testnet \
      -datadir=/data \
      -exportdir=/data \
      -server=1 \
      -printtoconsole=1 \
      -rpcworkqueue=64 \
      -rpcclienttimeout=120 \
      -listen=1 \
      -bind=0.0.0.0 \
      ${TXINDEX_FLAG[@]+"${TXINDEX_FLAG[@]}"} \
      ${BOOTSTRAP_FLAGS[@]+"${BOOTSTRAP_FLAGS[@]}"} \
      ${PERF_FLAGS[@]+"${PERF_FLAGS[@]}"} \
      ${IBD_FLAGS[@]+"${IBD_FLAGS[@]}"} >/dev/null

  echo "waiting for testnet rpc..." >&2
  for _ in $(seq 1 60); do
    if ! docker ps -a --format '{{.Names}}' | grep -qx "${NAME_A}"; then
      echo "testnet container missing: ${NAME_A}" >&2
      exit 1
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx "${NAME_A}"; then
      echo "testnet container exited early: ${NAME_A}" >&2
      docker logs "${NAME_A}" >&2 || true
      exit 1
    fi
    if scripts/junocash/testnet/cli.sh getblockcount >/dev/null 2>&1; then
      echo "testnet ready" >&2
      exit 0
    fi
    sleep 1
  done

  docker logs --tail 200 "${NAME_A}" >&2 || true
  echo "testnet rpc did not become ready" >&2
  exit 1
fi

docker run -d \
  ${PLATFORM_FLAG[@]+"${PLATFORM_FLAG[@]}"} \
  --name "${NAME_B}" \
  --network "${NETWORK}" \
  ${USER_FLAG[@]+"${USER_FLAG[@]}"} \
  -v "$(pwd)/${JUNOCASH_ROOT}:/opt/junocash:ro" \
  -v "${DATA_DIR_B_HOST}:/data" \
  "${IMAGE}" \
  /opt/junocash/bin/junocashd \
    -testnet \
    -datadir=/data \
    -exportdir=/data \
    -server=1 \
    -printtoconsole=1 \
    -rpcworkqueue=64 \
    -rpcclienttimeout=120 \
    -dnsseed=0 \
    -listen=1 \
    -bind=0.0.0.0 \
    ${TXINDEX_FLAG[@]+"${TXINDEX_FLAG[@]}"} \
    ${PERF_FLAGS[@]+"${PERF_FLAGS[@]}"} \
    ${IBD_FLAGS[@]+"${IBD_FLAGS[@]}"} \
    -connect="${NAME_A}:18234" >/dev/null

docker run -d \
  ${PLATFORM_FLAG[@]+"${PLATFORM_FLAG[@]}"} \
  --name "${NAME_A}" \
  --network "${NETWORK}" \
  ${USER_FLAG[@]+"${USER_FLAG[@]}"} \
  -v "$(pwd)/${JUNOCASH_ROOT}:/opt/junocash:ro" \
  -v "${DATA_DIR_A_HOST}:/data" \
  "${IMAGE}" \
  /opt/junocash/bin/junocashd \
    -testnet \
    -datadir=/data \
    -exportdir=/data \
    -server=1 \
    -printtoconsole=1 \
    -rpcworkqueue=64 \
    -rpcclienttimeout=120 \
    -dnsseed=0 \
    -listen=1 \
    -bind=0.0.0.0 \
    ${TXINDEX_FLAG[@]+"${TXINDEX_FLAG[@]}"} \
    ${PERF_FLAGS[@]+"${PERF_FLAGS[@]}"} \
    ${IBD_FLAGS[@]+"${IBD_FLAGS[@]}"} \
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
