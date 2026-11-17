#!/usr/bin/env bash
# HTTPS HTTP/2 GET with curl 8.23, then RFC 8441 extended CONNECT with
# libnghttp2. curl's own wss:// URL is not this second flight.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
built="$(bash "$root/build_tls.sh")"
curl_bin="$(printf '%s\n' "$built" | sed -n '1p')"
h2="$(printf '%s\n' "$built" | sed -n '2p')"
openssl_lib="$(cd "$(dirname "$(bash "$repo/tool/interop/openssl/build.sh" | tail -n 1)")/../lib" && pwd)"
export LD_LIBRARY_PATH="${openssl_lib}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-$repo/tool/interop/openssl/openssl.cnf}"
cd "$repo"
echo "== curl 8.23 HTTP/2 GET =="
dart run tool/interop/nghttp2-curl/h2_get_flight.dart "$curl_bin"
echo "== libnghttp2 extended CONNECT =="
dart run tool/interop/nghttp2-curl/h2_connect_flight.dart "$h2"
