#!/usr/bin/env bash
set -euo pipefail

REPO="juno-cash/junocash"
VERSION="${JUNO_JUNOCASH_VERSION:-0.9.8}"

ASSET="junocash-${VERSION}-linux64.tar.gz"
SUMS="SHA256SUMS"

BASE_DIR="tmp/junocash"
RELEASE_DIR="${BASE_DIR}/releases/v${VERSION}"
TARBALL_PATH="${RELEASE_DIR}/${ASSET}"
SUMS_PATH="${RELEASE_DIR}/${SUMS}"

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
  "https://github.com/${REPO}/releases/download/v${VERSION}/${SUMS}" \
  "${SUMS_PATH}"

download_if_missing \
  "https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}" \
  "${TARBALL_PATH}"

expected_sha="$(python3 - <<PY
import re
from pathlib import Path
asset = ${ASSET!r}
for line in Path(${SUMS_PATH!r}).read_text().splitlines():
    m = re.match(r'^([0-9a-fA-F]{64})\\s+\\*?(.+)$', line.strip())
    if not m:
        continue
    sha, name = m.group(1).lower(), m.group(2).strip()
    if name == asset:
        print(sha)
        raise SystemExit(0)
raise SystemExit(1)
PY)"

got_sha="$(python3 - <<PY
import hashlib
from pathlib import Path
h = hashlib.sha256()
with Path(${TARBALL_PATH!r}).open('rb') as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b''):
        h.update(chunk)
print(h.hexdigest())
PY)"

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

