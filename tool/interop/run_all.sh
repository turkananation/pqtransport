#!/usr/bin/env bash
# Run every peer interop in tool/interop. Exits non-zero on the first failure.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
echo "== nghttp2/curl =="
bash "$dir/nghttp2-curl/run.sh"
echo "== nghttp3 QPACK =="
bash "$dir/nghttp3-qpack/run.sh"
echo "all interops passed"
