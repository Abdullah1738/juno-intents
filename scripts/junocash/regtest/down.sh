#!/usr/bin/env bash
set -euo pipefail

NAME="${JUNO_REGTEST_CONTAINER_NAME:-juno-regtest}"

docker rm -f "${NAME}" >/dev/null 2>&1 || true

