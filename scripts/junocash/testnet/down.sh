#!/usr/bin/env bash
set -euo pipefail

NAME_A="${JUNO_TESTNET_CONTAINER_NAME_A:-juno-testnet-a}"
NAME_B="${JUNO_TESTNET_CONTAINER_NAME_B:-juno-testnet-b}"

docker stop -t "${JUNO_TESTNET_DOCKER_STOP_TIMEOUT_SECS:-30}" "${NAME_A}" "${NAME_B}" >/dev/null 2>&1 || true
docker rm -f "${NAME_A}" "${NAME_B}" >/dev/null 2>&1 || true
