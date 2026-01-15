#!/usr/bin/env bash
set -euo pipefail

NAME="${JUNO_TESTNET_CONTAINER_NAME_A:-juno-testnet-a}"

docker exec "${NAME}" /opt/junocash/bin/junocash-cli -testnet -datadir=/data "$@"

