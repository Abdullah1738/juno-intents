#!/usr/bin/env bash
set -euo pipefail

NAME="${JUNO_REGTEST_CONTAINER_NAME:-juno-regtest}"

docker exec "${NAME}" /opt/junocash/bin/junocash-cli -regtest -datadir=/data "$@"

