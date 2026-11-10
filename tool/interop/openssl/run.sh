#!/usr/bin/env bash
# OpenSSL 3.5.9 peer. Fails if a flight does not finish. No dart:ffi.
#
# TLS: PqTlsClient to s_server, s_client against PqTlsSocket, and the
# classical reverse rows (s_client -groups). QUIC: s_client -quic
# against PqQuicConn.server, then the reverse, PqQuicConn.client
# against demos/quic/server.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
bin="$(bash "$root/build.sh" | tail -n 1)"
lib="$(cd "$(dirname "$bin")/../lib" && pwd)"
export LD_LIBRARY_PATH="${lib}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-$root/openssl.cnf}"
known="$root/../boringssl/.build/bin/boringssl_verify"
got="$(bash "$root/../boringssl/build.sh" | tail -n 1)"
if [ -x "$got" ]; then
  BORINGSSL_VERIFY="$got"
elif [ -x "$known" ]; then
  echo "boringssl build stdout was not the executable; using $known" >&2
  echo "stdout was: [$got]" >&2
  BORINGSSL_VERIFY="$known"
else
  echo "boringssl_verify is not executable" >&2
  echo "stdout was: [$got]" >&2
  ls -l "$(dirname "$known")" >&2 || true
  exit 1
fi
export BORINGSSL_VERIFY
bash "$root/build_curl.sh" >/dev/null
demo="$(bash "$root/build_quic_demo.sh" | tail -n 1)"
cd "$repo"
echo "== OpenSSL TLS: client, server, and reverse =="
dart run tool/interop/openssl/handshake.dart "$bin"
echo "== OpenSSL QUIC: s_client against PqQuicConn.server =="
dart run tool/interop/openssl/quic_flight.dart "$bin"
echo "== OpenSSL QUIC reverse: PqQuicConn.client against demos/quic/server =="
dart run tool/interop/openssl/quic_client_flight.dart "$bin" "$demo"
echo "== curl HTTP/1.1 against PqHttpServer =="
dart run tool/interop/openssl/http1_server_flight.dart \
  "$root/.build/curl/bin/curl"
