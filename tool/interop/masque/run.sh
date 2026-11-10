#!/usr/bin/env bash
# masque-go v0.6.0 and connect-ip-go v0.6.0, both on quic-go v0.63.0.
# Their clients, our HTTP/3 server. ML-DSA-65 is checked by Go.
# Payloads are QUIC DATAGRAMs. ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT
# are Capsule Protocol TLVs. Not the reverse direction.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
build="$root/.build"
mkdir -p "$build"
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q 'go1\.2[7-9]'; then
  curl -fsSL --retry 5 -o "$build/go.tgz" https://go.dev/dl/go1.27.3.linux-amd64.tar.gz
  rm -rf "$build/go"
  tar -C "$build" -xzf "$build/go.tgz"
  export PATH="$build/go/bin:$PATH"
fi
if [[ ! -x "$build/udp-client" ]]; then
  (cd "$root/udp_client" && go mod tidy && go build -o "$build/udp-client" .)
fi
if [[ ! -x "$build/ip-client" ]]; then
  (cd "$root/ip_client" && go mod tidy && go build -o "$build/ip-client" .)
fi
cd "$repo"
echo "== masque-go CONNECT-UDP =="
dart run tool/interop/masque/udp_flight.dart "$build/udp-client"
echo "== connect-ip-go CONNECT-IP =="
dart run tool/interop/masque/ip_flight.dart "$build/ip-client"
