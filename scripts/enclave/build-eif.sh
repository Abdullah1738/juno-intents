#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.."; pwd)"

IMAGE_TAG="${JUNO_EIF_IMAGE_TAG:-juno-intents/nitro-operator-enclave:$(git -C "${ROOT}" rev-parse --short HEAD)}"
OUT_DIR="${JUNO_EIF_OUT_DIR:-${ROOT}/tmp/enclave}"
OUT_EIF="${JUNO_EIF_OUT_EIF:-${OUT_DIR}/operator.eif}"

export NITRO_CLI_ARTIFACTS="${NITRO_CLI_ARTIFACTS:-${OUT_DIR}/nitro-cli-artifacts}"
export NITRO_CLI_BLOBS="${NITRO_CLI_BLOBS:-/usr/share/nitro_enclaves/blobs/}"

require_cmd() {
  if ! command -v "$1" >/dev/null; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd nitro-cli

mkdir -p "${OUT_DIR}"
mkdir -p "${NITRO_CLI_ARTIFACTS}"

echo "building docker image: ${IMAGE_TAG}" >&2
docker build --platform linux/amd64 -f "${ROOT}/enclave/operator/Dockerfile" -t "${IMAGE_TAG}" "${ROOT}"

echo "building EIF: ${OUT_EIF}" >&2
nitro-cli build-enclave --docker-uri "${IMAGE_TAG}" --output-file "${OUT_EIF}"

echo "describing EIF..." >&2
DESCRIBE_JSON="$(nitro-cli describe-eif --eif-path "${OUT_EIF}")"
printf '%s\n' "${DESCRIBE_JSON}"

pcr0="$(python3 - <<'PY' <<<"${DESCRIBE_JSON}" 2>/dev/null || true
import json,sys
obj=json.load(sys.stdin)
m=obj.get("Measurements") or obj.get("measurements") or {}
print(m.get("PCR0") or m.get("pcr0") or "")
PY
)"
if [[ -n "${pcr0}" ]]; then
  echo "pcr0=${pcr0}" >&2
fi

if command -v sha256sum >/dev/null; then
  echo "eif_sha256=$(sha256sum "${OUT_EIF}" | awk '{print $1}')" >&2
elif command -v shasum >/dev/null; then
  echo "eif_sha256=$(shasum -a 256 "${OUT_EIF}" | awk '{print $1}')" >&2
fi

echo "eif_path=${OUT_EIF}" >&2
