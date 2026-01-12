#!/usr/bin/env bash
set -euo pipefail

scripts/junocash/regtest/up.sh

jcli() {
  scripts/junocash/regtest/cli.sh "$@"
}

echo "mining coinbase blocks..." >&2
jcli generate 110 >/dev/null

account="$(jcli z_getnewaccount | python3 -c 'import json,sys; print(json.load(sys.stdin)["account"])')"
ua="$(jcli z_getaddressforaccount "${account}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')"

echo "shielding coinbase to orchard UA..." >&2
shield_limit="${JUNO_REGTEST_SHIELD_LIMIT:-1}"
opid="$(jcli z_shieldcoinbase "*" "${ua}" null "${shield_limit}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["opid"])')"

echo "waiting for shield operation..." >&2
txid=""
wait_secs="${JUNO_REGTEST_SHIELD_WAIT_SECS:-600}"
for _ in $(seq 1 "${wait_secs}"); do
  if ! res="$(jcli z_getoperationresult "[\"${opid}\"]" 2>&1)"; then
    echo "z_getoperationresult failed; raw output:" >&2
    printf '%s\n' "${res}" >&2
    exit 1
  fi
  txid="$(printf '%s' "${res}" | python3 - <<'PY'
import json, sys
try:
    items = json.load(sys.stdin)
except json.JSONDecodeError as e:
    raise SystemExit(3)

if not items:
    raise SystemExit(1)
it = items[0]
status = it.get("status")
if status == "success":
    print(it["result"]["txid"])
    raise SystemExit(0)
err = it.get("error", {})
msg = err.get("message") if isinstance(err, dict) else None
sys.stderr.write(f"shield operation failed (status={status} message={msg})\\n")
raise SystemExit(2)
PY
  )" && break || {
    ec=$?
    if [[ "${ec}" == "1" ]]; then
      sleep 1
      continue
    fi
    if [[ "${ec}" == "2" ]]; then
      echo "shield operation failed; raw z_getoperationresult output:" >&2
      printf '%s\n' "${res}" >&2
      exit 1
    fi
    if [[ "${ec}" == "3" ]]; then
      echo "z_getoperationresult returned non-JSON; raw output:" >&2
      printf '%s\n' "${res}" >&2
      exit 1
    fi
    echo "unexpected z_getoperationresult parser exit code: ${ec}" >&2
    printf '%s\n' "${res}" >&2
    exit 1
  }
done

if [[ -z "${txid}" ]]; then
  echo "shielding operation did not complete" >&2
  jcli z_getoperationstatus "[\"${opid}\"]" >&2 || true
  docker logs --tail 200 "${JUNO_REGTEST_CONTAINER_NAME:-juno-regtest}" >&2 || true
  exit 1
fi

echo "mining confirmation block..." >&2
jcli generate 1 >/dev/null

echo "waiting for orchard note to be spendable..." >&2
for _ in $(seq 1 60); do
  if jcli z_listunspent 1 9999999 false | python3 - <<'PY' >/dev/null
import json, sys
notes = json.load(sys.stdin)
ok = any(n.get("pool") == "orchard" and n.get("spendable") and float(n.get("amount", 0)) > 0 for n in notes)
raise SystemExit(0 if ok else 1)
PY
  then
    echo "fixture ready (txid=${txid})" >&2
    exit 0
  fi
  sleep 1
done

echo "orchard note did not appear in z_listunspent" >&2
exit 1
