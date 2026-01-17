#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

DOCKERFILE_REL="${JUNO_EIF_DOCKERFILE:-enclave/operator/Dockerfile}"
DOCKERFILE_PATH="${ROOT}/${DOCKERFILE_REL}"

IMAGE_TAG="${JUNO_EIF_IMAGE_TAG:-juno-intents/nitro-operator-enclave:$(git -C "${ROOT}" rev-parse --short HEAD)}"
OUT_DIR="${JUNO_EIF_OUT_DIR:-${ROOT}/tmp/enclave}"
OUT_EIF="${JUNO_EIF_OUT_EIF:-${OUT_DIR}/operator.eif}"

export NITRO_CLI_ARTIFACTS="${NITRO_CLI_ARTIFACTS:-${OUT_DIR}/nitro-cli-artifacts}"
export NITRO_CLI_BLOBS="${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs/}"

# Make EIF builds as deterministic as possible across hosts.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export TZ="${TZ:-UTC}"

require_cmd() {
  if ! command -v "$1" >/dev/null; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd nitro-cli

if [[ ! -f "${DOCKERFILE_PATH}" ]]; then
  echo "dockerfile not found: ${DOCKERFILE_PATH}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
mkdir -p "${NITRO_CLI_ARTIFACTS}"

echo "building docker image: ${IMAGE_TAG}" >&2
if [[ "${JUNO_EIF_DETERMINISTIC_CONTEXT:-1}" == "1" ]]; then
  echo "building deterministic docker context..." >&2
  ROOT_FOR_CTX="${ROOT}" DOCKERFILE_FOR_CTX="${DOCKERFILE_PATH}" python3 - <<'PY' \
    | docker build --platform linux/amd64 -f Dockerfile -t "${IMAGE_TAG}" -
import io
import os
import stat
import subprocess
import sys
import tarfile

root = os.environ["ROOT_FOR_CTX"]

try:
  out = subprocess.check_output(["git", "-C", root, "ls-files", "-z"])
except Exception:
  raise SystemExit(1)

paths = []
for b in out.split(b"\0"):
  if not b:
    continue
  paths.append(b.decode("utf-8", errors="strict"))
paths.sort()

dockerfile_path = os.environ["DOCKERFILE_FOR_CTX"]
with open(dockerfile_path, "rb") as f:
  dockerfile = f.read()

def add_bytes(tf: tarfile.TarFile, name: str, content: bytes, mode: int = 0o644) -> None:
  ti = tarfile.TarInfo(name=name)
  ti.size = len(content)
  ti.mtime = 0
  ti.uid = 0
  ti.gid = 0
  ti.uname = ""
  ti.gname = ""
  ti.mode = mode
  tf.addfile(ti, io.BytesIO(content))

with tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.GNU_FORMAT) as tf:
  add_bytes(tf, "Dockerfile", dockerfile, mode=0o644)

  for rel in paths:
    src = os.path.join(root, rel)
    try:
      st = os.lstat(src)
    except FileNotFoundError:
      continue

    ti = tarfile.TarInfo(name=rel)
    ti.mtime = 0
    ti.uid = 0
    ti.gid = 0
    ti.uname = ""
    ti.gname = ""
    ti.mode = st.st_mode & 0o777

    if stat.S_ISLNK(st.st_mode):
      ti.type = tarfile.SYMTYPE
      ti.linkname = os.readlink(src)
      ti.size = 0
      tf.addfile(ti)
      continue

    if stat.S_ISREG(st.st_mode):
      ti.size = st.st_size
      with open(src, "rb") as f:
        tf.addfile(ti, f)
      continue

    if stat.S_ISDIR(st.st_mode):
      ti.type = tarfile.DIRTYPE
      ti.size = 0
      tf.addfile(ti)
      continue
PY
else
  docker build --platform linux/amd64 -f "${DOCKERFILE_PATH}" -t "${IMAGE_TAG}" "${ROOT}"
fi

echo "building EIF: ${OUT_EIF}" >&2
nitro-cli build-enclave --docker-uri "${IMAGE_TAG}" --output-file "${OUT_EIF}"

echo "describing EIF..." >&2
DESCRIBE_OUT="$(nitro-cli describe-eif --eif-path "${OUT_EIF}" 2>&1)"
printf '%s\n' "${DESCRIBE_OUT}"

pcr0="$(python3 -c 'import json,sys; obj=json.load(sys.stdin); m=obj.get("Measurements") or obj.get("measurements") or {}; print(m.get("PCR0") or m.get("pcr0") or "")' <<<"${DESCRIBE_OUT}" 2>/dev/null || true)"
if [[ -z "${pcr0}" ]]; then
  pcr0="$(printf '%s\n' "${DESCRIBE_OUT}" | sed -nE 's/.*PCR0[^0-9a-fA-F]*([0-9a-fA-F]{96}).*/\1/p' | head -n 1 || true)"
fi
if [[ -n "${pcr0}" ]]; then
  echo "pcr0=${pcr0}" >&2
fi

if command -v sha256sum >/dev/null; then
  echo "eif_sha256=$(sha256sum "${OUT_EIF}" | awk '{print $1}')" >&2
elif command -v shasum >/dev/null; then
  echo "eif_sha256=$(shasum -a 256 "${OUT_EIF}" | awk '{print $1}')" >&2
fi

echo "eif_path=${OUT_EIF}" >&2
