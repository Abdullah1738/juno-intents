#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

VERSION="${JUNO_BERKELEY_DB_VERSION:-6.2.32}"
TARBALL="db-${VERSION}.tar.gz"
URL="https://download.oracle.com/berkeley-db/${TARBALL}"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

maybe_apt_install() {
  local pkgs=("$@")
  if ! have_cmd apt-get; then
    return 1
  fi
  local -a sudo_cmd=()
  if [[ "$(id -u)" != "0" ]] && have_cmd sudo; then
    sudo_cmd=(sudo)
  fi
  "${sudo_cmd[@]}" apt-get update >/dev/null
  "${sudo_cmd[@]}" apt-get install -y --no-install-recommends "${pkgs[@]}" >/dev/null
}

if ! have_cmd curl; then
  if ! maybe_apt_install curl ca-certificates; then
    echo "missing required tool: curl" >&2
    exit 1
  fi
fi
if ! have_cmd make || ! have_cmd gcc || ! have_cmd g++; then
  if ! maybe_apt_install build-essential; then
    echo "missing required build tools (need: make, gcc, g++)" >&2
    exit 1
  fi
fi

expected_sha256=""
case "${VERSION}" in
  6.2.32)
    expected_sha256="a9c5e2b004a5777aa03510cfe5cd766a4a3b777713406b02809c17c8e0e7a8fb"
    ;;
esac
if [[ -z "${expected_sha256}" ]]; then
  echo "unsupported Berkeley DB version: ${VERSION} (no pinned sha256)" >&2
  exit 2
fi

BASE_DIR="${ROOT}/tmp/berkeleydb"
SRC_DIR="${BASE_DIR}/db-${VERSION}"
TARBALL_PATH="${BASE_DIR}/${TARBALL}"
PREFIX_DIR="${BASE_DIR}/install/db-${VERSION}"
MARKER="${PREFIX_DIR}/.installed.ok"
OUT="${PREFIX_DIR}/bin/db_dump"

mkdir -p "${BASE_DIR}"

sha256_file() {
  local path="$1"
  python3 - "$path" <<'PY'
import hashlib
import sys
from pathlib import Path

p = Path(sys.argv[1])
h = hashlib.sha256()
with p.open("rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
print(h.hexdigest())
PY
}

download_if_missing() {
  local url="$1"
  local out="$2"
  if [[ -f "${out}" ]]; then
    return 0
  fi
  local tmp="${out}.tmp"
  rm -f "${tmp}" >/dev/null 2>&1 || true
  curl -fsSL --retry 8 --retry-delay 5 --retry-all-errors "${url}" -o "${tmp}"
  mv "${tmp}" "${out}"
}

if [[ ! -f "${MARKER}" ]]; then
  download_if_missing "${URL}" "${TARBALL_PATH}"

  got_sha256="$(sha256_file "${TARBALL_PATH}")"
  if [[ "${got_sha256}" != "${expected_sha256}" ]]; then
    echo "berkeleydb tarball sha256 mismatch:" >&2
    echo "  expected: ${expected_sha256}" >&2
    echo "  got:      ${got_sha256}" >&2
    echo "  file:     ${TARBALL_PATH}" >&2
    exit 1
  fi

  rm -rf "${SRC_DIR}" "${PREFIX_DIR}"
  mkdir -p "${SRC_DIR}" "${PREFIX_DIR}"
  tar -xzf "${TARBALL_PATH}" -C "${BASE_DIR}"

  build_dir="${SRC_DIR}/build_unix"
  if [[ ! -d "${build_dir}" ]]; then
    echo "unexpected berkeleydb source layout; missing: ${build_dir}" >&2
    exit 1
  fi

  (
    cd "${build_dir}"
    log="${BASE_DIR}/build-db-${VERSION}.log"
    rm -f "${log}"
    {
      ../dist/configure --prefix="${PREFIX_DIR}" --enable-cxx
      make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
      make install
    } >>"${log}" 2>&1 || {
      echo "failed to build/install berkeleydb ${VERSION} (tailing log): ${log}" >&2
      tail -n 80 "${log}" >&2 || true
      exit 1
    }
  )

  if [[ ! -x "${OUT}" ]]; then
    echo "db_dump not found after install: ${OUT}" >&2
    exit 1
  fi
  touch "${MARKER}"
fi

echo "${OUT}"
