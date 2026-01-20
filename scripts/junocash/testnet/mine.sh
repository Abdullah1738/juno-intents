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

sync_timeout="${JUNO_TESTNET_SYNC_TIMEOUT_SECS:-7200}"
if ! [[ "${sync_timeout}" =~ ^[0-9]+$ ]] || [[ "${sync_timeout}" -le 0 ]]; then
  echo "invalid JUNO_TESTNET_SYNC_TIMEOUT_SECS: ${sync_timeout} (using 7200)" >&2
  sync_timeout="7200"
fi
sync_poll_secs="${JUNO_TESTNET_SYNC_POLL_SECS:-5}"
if ! [[ "${sync_poll_secs}" =~ ^[0-9]+$ ]] || [[ "${sync_poll_secs}" -le 0 ]]; then
  sync_poll_secs="5"
fi
sync_progress_secs="${JUNO_TESTNET_SYNC_PROGRESS_SECS:-30}"
if ! [[ "${sync_progress_secs}" =~ ^[0-9]+$ ]] || [[ "${sync_progress_secs}" -le 0 ]]; then
  sync_progress_secs="30"
fi

echo "waiting for testnet sync (initial_block_download_complete=true)..." >&2
elapsed=0
while [[ "${elapsed}" -lt "${sync_timeout}" ]]; do
  info="$(jcli getblockchaininfo 2>/dev/null || true)"
  if [[ -n "${info}" ]]; then
    complete="$(
      python3 -c 'import json,sys
try:
  j=json.load(sys.stdin)
except Exception:
  print("0"); raise SystemExit(0)
print("1" if j.get("initial_block_download_complete") else "0")
' <<<"${info}"
    )"
    if [[ "${complete}" == "1" ]]; then
      break
    fi
    if (( elapsed % sync_progress_secs == 0 )); then
      summary="$(
        python3 -c 'import json,sys
try: j=json.load(sys.stdin)
except Exception: print(""); raise SystemExit(0)
blocks=j.get("blocks"); headers=j.get("headers"); est=j.get("estimatedheight")
print(f"blocks={blocks} headers={headers} estimatedheight={est}")
' <<<"${info}"
      )"
      if [[ -n "${summary}" ]]; then
        echo "sync_status ${summary} elapsed=${elapsed}s" >&2
      fi
    fi
  fi
  sleep "${sync_poll_secs}"
  elapsed="$((elapsed + sync_poll_secs))"
done
if [[ "${elapsed}" -ge "${sync_timeout}" ]]; then
  echo "timed out waiting for testnet sync (elapsed=${elapsed}s timeout=${sync_timeout}s)" >&2
  exit 1
fi

start="$(jcli getblockcount)"
if ! [[ "${start}" =~ ^[0-9]+$ ]]; then
  echo "unexpected getblockcount response: ${start}" >&2
  exit 1
fi
threads="${JUNO_TESTNET_GENPROCLIMIT:--1}"

timeout="${JUNO_TESTNET_MINE_TIMEOUT_SECS:-1800}"
if ! [[ "${timeout}" =~ ^[0-9]+$ ]] || [[ "${timeout}" -le 0 ]]; then
  echo "invalid JUNO_TESTNET_MINE_TIMEOUT_SECS: ${timeout} (using 1800)" >&2
  timeout="1800"
fi

txcount_start="$(
  jcli getwalletinfo | python3 -c 'import json,sys
j=json.load(sys.stdin)
print(int(j.get("txcount") or 0))
'
)"
if ! [[ "${txcount_start}" =~ ^[0-9]+$ ]]; then
  echo "unexpected getwalletinfo txcount: ${txcount_start}" >&2
  exit 1
fi
txcount_target="$((txcount_start + want))"

progress_secs="${JUNO_TESTNET_MINE_PROGRESS_SECS:-30}"
if ! [[ "${progress_secs}" =~ ^[0-9]+$ ]] || [[ "${progress_secs}" -le 0 ]]; then
  progress_secs="30"
fi

echo "mining ${want} blocks (chain height starts at ${start})... threads=${threads} timeout=${timeout}s txcount_start=${txcount_start}" >&2
jcli setgenerate true "${threads}" >/dev/null

last_height="${start}"
for ((i=1; i<=timeout; i++)); do
  height="$(jcli getblockcount)"
  txcount_now="$(
    jcli getwalletinfo | python3 -c 'import json,sys
j=json.load(sys.stdin)
print(int(j.get("txcount") or 0))
'
  )"
  mined_blocks="$((txcount_now - txcount_start))"
  if [[ "${txcount_now}" -ge "${txcount_target}" ]]; then
    jcli setgenerate false >/dev/null || true
    echo "mined_blocks=${mined_blocks} height=${height}" >&2
    exit 0
  fi
  if [[ "${height}" != "${last_height}" ]] || (( i % progress_secs == 0 )); then
    echo "height=${height} mined_blocks=${mined_blocks}/${want} elapsed=${i}s" >&2
    last_height="${height}"
  fi
  sleep 1
done

final_height="$(jcli getblockcount 2>/dev/null || true)"
final_txcount="$(jcli getwalletinfo 2>/dev/null | python3 -c 'import json,sys
try:
  j=json.load(sys.stdin)
except Exception:
  print(0); raise SystemExit(0)
print(int(j.get("txcount") or 0))
')"
final_mined="$((final_txcount - txcount_start))"
jcli setgenerate false >/dev/null || true
echo "timed out waiting to mine ${want} blocks (mined_blocks=${final_mined} height=${final_height})" >&2
exit 1
