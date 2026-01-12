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
opid="$(jcli z_shieldcoinbase "*" "${ua}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["opid"])')"

echo "waiting for shield operation..." >&2
txid=""
for _ in $(seq 1 120); do
  res="$(jcli z_getoperationresult "[\"${opid}\"]")"
  txid="$(printf '%s' "${res}" | python3 - <<'PY'
import json, sys
items = json.load(sys.stdin)
if not items:
    raise SystemExit(1)
it = items[0]
if it.get("status") != "success":
    raise SystemExit(2)
print(it["result"]["txid"])
PY
  )" || true
  if [[ -n "${txid}" ]]; then
    break
  fi
  sleep 1
done

if [[ -z "${txid}" ]]; then
  echo "shielding operation did not complete" >&2
  jcli z_getoperationstatus "[\"${opid}\"]" >&2 || true
  exit 1
fi

echo "mining confirmation block..." >&2
jcli generate 1 >/dev/null

echo "waiting for orchard note to be spendable..." >&2
for _ in $(seq 1 60); do
  if jcli z_listunspent 1 9999999 false | python3 - <<'PY' >/dev/null; then
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

