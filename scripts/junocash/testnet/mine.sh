#!/usr/bin/env bash
set -euo pipefail

want="${1:-}"
if [[ "${want}" == "" ]]; then
  echo "usage: $0 <blocks>" >&2
  exit 2
fi
if ! [[ "${want}" =~ ^[0-9]+$ ]] || [[ "${want}" -le 0 ]]; then
  echo "blocks must be a positive integer (got: ${want})" >&2
  exit 2
fi

scripts/junocash/testnet/up.sh >/dev/null

jcli() { scripts/junocash/testnet/cli.sh "$@"; }

start="$(jcli getblockcount)"
if ! [[ "${start}" =~ ^[0-9]+$ ]]; then
  echo "unexpected getblockcount response: ${start}" >&2
  exit 1
fi
target="$((start + want))"
threads="${JUNO_TESTNET_GENPROCLIMIT:--1}"

timeout="${JUNO_TESTNET_MINE_TIMEOUT_SECS:-1800}"
if ! [[ "${timeout}" =~ ^[0-9]+$ ]] || [[ "${timeout}" -le 0 ]]; then
  echo "invalid JUNO_TESTNET_MINE_TIMEOUT_SECS: ${timeout} (using 1800)" >&2
  timeout="1800"
fi

progress_secs="${JUNO_TESTNET_MINE_PROGRESS_SECS:-30}"
if ! [[ "${progress_secs}" =~ ^[0-9]+$ ]] || [[ "${progress_secs}" -le 0 ]]; then
  progress_secs="30"
fi

echo "mining ${want} blocks (from ${start} to ${target})... threads=${threads} timeout=${timeout}s" >&2
jcli setgenerate true "${threads}" >/dev/null

last_height="${start}"
for ((i=1; i<=timeout; i++)); do
  height="$(jcli getblockcount)"
  if [[ "${height}" -ge "${target}" ]]; then
    jcli setgenerate false >/dev/null || true
    echo "mined to height ${height}" >&2
    exit 0
  fi
  if [[ "${height}" != "${last_height}" ]] || (( i % progress_secs == 0 )); then
    echo "height=${height} target=${target} elapsed=${i}s" >&2
    last_height="${height}"
  fi
  sleep 1
done

final_height="$(jcli getblockcount 2>/dev/null || true)"
jcli setgenerate false >/dev/null || true
echo "timed out waiting to reach height ${target} (height=${final_height})" >&2
exit 1
