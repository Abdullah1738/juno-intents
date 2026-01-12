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
  compact="$(printf '%s' "${res}" | tr -d ' \n\r\t')"
  if [[ "${compact}" == "[]" ]]; then
    sleep 1
    continue
  fi

  txid="$(printf '%s' "${res}" | python3 -c $'import json,sys\nitems=json.load(sys.stdin)\nit=items[0]\nstatus=it.get(\"status\")\nif status==\"success\":\n    print(it[\"result\"][\"txid\"])\n    sys.exit(0)\nerr=it.get(\"error\", {})\nmsg=err.get(\"message\") if isinstance(err, dict) else None\nprint(f\"shield operation failed (status={status} message={msg})\", file=sys.stderr)\nsys.exit(2)\n')" && break || {
    ec=$?
    if [[ "${ec}" == "2" ]]; then
      echo "shield operation failed; raw z_getoperationresult output:" >&2
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
  if jcli z_listunspent 1 9999999 false | python3 -c 'import json,sys; notes=json.load(sys.stdin); ok=any(n.get(\"pool\")==\"orchard\" and n.get(\"spendable\") and float(n.get(\"amount\",0))>0 for n in notes); sys.exit(0 if ok else 1)' >/dev/null
  then
    echo "fixture ready (txid=${txid})" >&2
    exit 0
  fi
  sleep 1
done

echo "orchard note did not appear in z_listunspent" >&2
exit 1
