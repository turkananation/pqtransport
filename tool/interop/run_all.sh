#!/usr/bin/env bash
# Run every peer interop in tool/interop. Exits non-zero on the first failure.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)"
echo "== nghttp2/curl =="
bash "$dir/nghttp2-curl/run.sh"
echo "== nghttp3 QPACK =="
bash "$dir/nghttp3-qpack/run.sh"
echo "== OpenSSL 3.5 X25519MLKEM768 =="
bash "$dir/openssl/run.sh"
echo "== BoringSSL 0.20261020.0 X25519MLKEM768 =="
bash "$dir/boringssl/run.sh"
echo "== quiche QUIC, BoringSSL 0.20261020.0 =="
bash "$dir/quiche/run.sh"
echo "== masque-go CONNECT-UDP and connect-ip-go CONNECT-IP =="
bash "$dir/masque/run.sh"
echo "all interops passed"
