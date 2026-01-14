#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

PROFILE="juno"
REGION="${JUNO_AWS_REGION:-us-east-1}"

REF=""
TAG=""
PRERELEASE=0
DRAFT=0

usage() {
  cat <<'USAGE' >&2
Usage:
  scripts/release/eif.sh [--ref <git-ref>] [--tag <tag>] [--prerelease] [--draft]

Notes:
  - Builds the EIF on a short-lived AWS EC2 builder via SSM (uses --profile juno).
  - Downloads the EIF + metadata JSON to tmp/, then publishes them as GitHub release assets.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --ref)
      REF="${2:-}"
      shift 2
      ;;
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --prerelease)
      PRERELEASE=1
      shift 1
      ;;
    --draft)
      DRAFT=1
      shift 1
      ;;
    *)
      echo "unexpected argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${REF}" ]]; then
  REF="$(git -C "${ROOT}" rev-parse HEAD)"
fi

GIT_SHA="$(git -C "${ROOT}" rev-parse "${REF}^{commit}")"
SHORT_SHA="$(git -C "${ROOT}" rev-parse --short=12 "${GIT_SHA}")"

if [[ -z "${TAG}" ]]; then
  TAG="eif-operator-${SHORT_SHA}"
fi

if ! command -v gh >/dev/null; then
  echo "missing required command: gh" >&2
  exit 1
fi
if ! command -v aws >/dev/null; then
  echo "missing required command: aws" >&2
  exit 1
fi

if gh release view "${TAG}" >/dev/null 2>&1; then
  echo "release already exists: ${TAG}" >&2
  exit 1
fi

OUT_DIR="${ROOT}/tmp/eif/${TAG}"
mkdir -p "${OUT_DIR}"

echo "building EIF for ${GIT_SHA} (tag=${TAG})..." >&2
"${ROOT}/scripts/aws/build-eif.sh" --ref "${GIT_SHA}" --download-dir "${OUT_DIR}" >/dev/null

if [[ ! -f "${OUT_DIR}/operator.eif" || ! -f "${OUT_DIR}/operator.meta.json" ]]; then
  echo "download did not produce expected files in: ${OUT_DIR}" >&2
  ls -la "${OUT_DIR}" >&2 || true
  exit 1
fi

KV_OUT="$(python3 - <<'PY' "${OUT_DIR}/operator.meta.json"
import json,sys
path=sys.argv[1]
with open(path,"r",encoding="utf-8") as f:
  meta=json.load(f)
for k in ("git_sha","pcr0","eif_sha256"):
  v=meta.get(k) or ""
  print(f"{k}={v}")
PY
)"
git_sha="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^git_sha=(.+)$/\1/p' | head -n 1)"
pcr0="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^pcr0=(.+)$/\1/p' | head -n 1)"
eif_sha256="$(printf '%s\n' "${KV_OUT}" | sed -nE 's/^eif_sha256=(.+)$/\1/p' | head -n 1)"

if [[ -z "${git_sha}" || -z "${pcr0}" || -z "${eif_sha256}" ]]; then
  echo "metadata missing required fields" >&2
  cat "${OUT_DIR}/operator.meta.json" >&2
  exit 1
fi

local_sha="$(
  python3 - <<'PY' "${OUT_DIR}/operator.eif"
import hashlib,sys
path=sys.argv[1]
h=hashlib.sha256()
with open(path,"rb") as f:
  for chunk in iter(lambda: f.read(1024*1024), b""):
    h.update(chunk)
print(h.hexdigest())
PY
)"
if [[ "${local_sha}" != "${eif_sha256}" ]]; then
  echo "EIF sha256 mismatch (meta=${eif_sha256} local=${local_sha})" >&2
  exit 1
fi

args=()
if [[ "${PRERELEASE}" == "1" ]]; then
  args+=(--prerelease)
fi
if [[ "${DRAFT}" == "1" ]]; then
  args+=(--draft)
fi

echo "creating GitHub release..." >&2
(
  cd "${ROOT}"
  gh release create "${TAG}" \
    "${OUT_DIR}/operator.eif" \
    "${OUT_DIR}/operator.meta.json" \
    --target "${git_sha}" \
    --title "Nitro EIF (operator) ${SHORT_SHA}" \
    --notes "git_sha=${git_sha}\npcr0=${pcr0}\neif_sha256=${eif_sha256}" \
    "${args[@]}"
)

url="$(
  cd "${ROOT}" \
    && gh release view "${TAG}" --json url -q .url 2>/dev/null \
    || true
)"
if [[ -n "${url}" ]]; then
  echo "release_url=${url}"
fi
echo "git_sha=${git_sha}"
echo "pcr0=${pcr0}"
echo "eif_sha256=${eif_sha256}"
