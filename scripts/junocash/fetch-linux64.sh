#!/usr/bin/env bash
set -euo pipefail

REPO="juno-cash/junocash"
VERSION="${JUNO_JUNOCASH_VERSION:-0.9.8}"

ASSET="junocash-${VERSION}-linux64.tar.gz"

BASE_DIR="tmp/junocash"
RELEASE_DIR="${BASE_DIR}/releases/v${VERSION}"
TARBALL_PATH="${RELEASE_DIR}/${ASSET}"

EXTRACT_BASE="${BASE_DIR}/v${VERSION}"
EXTRACT_ROOT="${EXTRACT_BASE}/junocash-${VERSION}"
MARKER="${EXTRACT_ROOT}/.extracted.ok"

mkdir -p "${RELEASE_DIR}"
mkdir -p "${EXTRACT_BASE}"

download_if_missing() {
  local url="$1"
  local out="$2"
  if [[ -f "${out}" ]]; then
    return 0
  fi
  curl -fsSL "${url}" -o "${out}"
}

download_if_missing \
  "https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}" \
  "${TARBALL_PATH}"

expected_sha=""
case "${ASSET}" in
  junocash-0.9.8-linux64.tar.gz)
    expected_sha="67aca81b97644525aaa997024b15815202a0ea68f378d9d0213b4a3cb2ed6960"
    ;;
esac
if [[ -z "${expected_sha}" ]]; then
  echo "no embedded sha256 for ${ASSET}; set JUNO_JUNOCASH_VERSION to a supported release" >&2
  exit 1
fi

got_sha="$(
  TARBALL_PATH="${TARBALL_PATH}" python3 - <<'PY'
import hashlib
from pathlib import Path
import os
h = hashlib.sha256()
with Path(os.environ["TARBALL_PATH"]).open('rb') as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b''):
        h.update(chunk)
print(h.hexdigest())
PY
)"

if [[ "${got_sha}" != "${expected_sha}" ]]; then
  echo "junocash tarball sha mismatch:" >&2
  echo "  expected: ${expected_sha}" >&2
  echo "  got:      ${got_sha}" >&2
  exit 1
fi

if [[ ! -f "${MARKER}" ]]; then
  rm -rf "${EXTRACT_ROOT}"
  tar -xzf "${TARBALL_PATH}" -C "${EXTRACT_BASE}"
  touch "${MARKER}"
fi

if [[ ! -x "${EXTRACT_ROOT}/bin/junocashd" ]]; then
  echo "junocashd not found after extract: ${EXTRACT_ROOT}/bin/junocashd" >&2
  exit 1
fi

echo "${EXTRACT_ROOT}"
