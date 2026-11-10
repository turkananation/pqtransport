#!/usr/bin/env bash
# quiche QUIC and HTTP/3, both directions. BoringSSL's bssl CLI has
# no QUIC transport, so this is the QUIC stack linked to that pin.
# Not curl --http3.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
bash "$repo/tool/interop/boringssl/build.sh" >/dev/null
verify="$repo/tool/interop/boringssl/.build/bin/boringssl_verify"
peer_tls="$(dirname "$verify")/boringssl_peer"
if [ ! -x "$peer_tls" ]; then
  echo "boringssl_peer is not executable" >&2
  exit 1
fi
quiche="$(bash "$root/build.sh" | tail -n 1)"
cd "$repo"
echo "== quiche QUIC: client against PqQuicConn.server =="
dart run tool/interop/quiche/quic_flight.dart "$quiche"
echo "== quiche QUIC reverse: PqQuicConn.client against quiche =="
dart run tool/interop/quiche/quic_client_flight.dart "$peer_tls" "$quiche"
echo "== quiche HTTP/3: client against PqHttp3Session =="
dart run tool/interop/quiche/h3_flight.dart "$quiche"
echo "== quiche HTTP/3 reverse: PqHttp3Session against quiche =="
dart run tool/interop/quiche/h3_client_flight.dart "$peer_tls" "$quiche"
