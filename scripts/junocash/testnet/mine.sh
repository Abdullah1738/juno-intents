#!/usr/bin/env bash
set -euo pipefail

want="${1:-}"
if [[ "${want}" == "" ]]; then
  echo "usage: $0 <blocks>" >&2
  exit 2
fi

scripts/junocash/testnet/up.sh >/dev/null

jcli() { scripts/junocash/testnet/cli.sh "$@"; }

start="$(jcli getblockcount)"
target="$((start + want))"
threads="${JUNO_TESTNET_GENPROCLIMIT:--1}"

echo "mining ${want} blocks (from ${start} to ${target})..." >&2
jcli setgenerate true "${threads}" >/dev/null

timeout="${JUNO_TESTNET_MINE_TIMEOUT_SECS:-1800}"
for _ in $(seq 1 "${timeout}"); do
  height="$(jcli getblockcount)"
  if [[ "${height}" -ge "${target}" ]]; then
    jcli setgenerate false >/dev/null || true
    echo "mined to height ${height}" >&2
    exit 0
  fi
  sleep 1
done

jcli setgenerate false >/dev/null || true
echo "timed out waiting to reach height ${target}" >&2
exit 1
