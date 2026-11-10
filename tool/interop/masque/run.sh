#!/usr/bin/env bash
# masque-go v0.6.0 and connect-ip-go v0.6.0, both on quic-go v0.63.0.
# Both directions. ML-DSA-65 is checked by the side that did not
# mint the leaf. Payloads are QUIC DATAGRAMs. ADDRESS_ASSIGN and
# ROUTE_ADVERTISEMENT are Capsule Protocol TLVs. The masque-go
# reverse response does not include capsule-protocol.
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
if [[ ! -x "$build/udp-proxy" ]]; then
  (cd "$root/udp_proxy" && go mod tidy && go build -o "$build/udp-proxy" .)
fi
if [[ ! -x "$build/ip-proxy" ]]; then
  (cd "$root/ip_proxy" && go mod tidy && go build -o "$build/ip-proxy" .)
fi
cd "$repo"
echo "== masque-go CONNECT-UDP =="
dart run tool/interop/masque/udp_flight.dart "$build/udp-client"
echo "== connect-ip-go CONNECT-IP =="
dart run tool/interop/masque/ip_flight.dart "$build/ip-client"
echo "== reverse CONNECT-UDP =="
dart run tool/interop/masque/udp_reverse_flight.dart "$build/udp-proxy"
echo "== reverse CONNECT-IP =="
dart run tool/interop/masque/ip_reverse_flight.dart "$build/ip-proxy"