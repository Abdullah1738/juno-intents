#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="${JUNO_REGTEST_DATA_DIR:-tmp/junocash-regtest}"
cleanup() {
  scripts/junocash/regtest/down.sh >/dev/null 2>&1 || true
}
trap cleanup EXIT

scripts/junocash/regtest/mk-fixture.sh >/dev/null

wallet_candidates=(
  "${DATA_DIR}/wallet.dat"
  "${DATA_DIR}/regtest/wallet.dat"
  "${DATA_DIR}/wallets/wallet.dat"
  "${DATA_DIR}/regtest/wallets/wallet.dat"
)
wallet=""
for p in "${wallet_candidates[@]}"; do
  if [[ -f "${p}" ]]; then
    wallet="${p}"
    break
  fi
done
if [[ -z "${wallet}" ]]; then
  echo "wallet.dat not found in ${DATA_DIR}" >&2
  exit 1
fi

db_dump="${JUNO_DB_DUMP:-db_dump}"
if [[ -x "/opt/homebrew/opt/berkeley-db/bin/db_dump" ]]; then
  db_dump="/opt/homebrew/opt/berkeley-db/bin/db_dump"
fi

cargo_bin="${CARGO:-cargo}"

${cargo_bin} run --quiet --manifest-path risc0/receipt/host/Cargo.toml --bin wallet_witness_v1 -- \
  --junocash-cli scripts/junocash/regtest/cli.sh \
  --wallet "${wallet}" \
  --db-dump "${db_dump}"

