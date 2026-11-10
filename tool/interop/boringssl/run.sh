#!/usr/bin/env bash
# BoringSSL 0.20261020.0 TLS peer. Client, server, and classical reverse.
# This pin's bssl CLI has no QUIC transport. SSL_QUIC_METHOD is the
# RFC 9001 hook a QUIC stack calls. It is not a QUIC implementation,
# and this script does not pretend otherwise.
# Fails if a flight does not finish. No dart:ffi.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
verify="$(bash "$root/build.sh" | tail -n 1)"
peer="$(dirname "$verify")/boringssl_peer"
cd "$repo"
echo "== BoringSSL TLS: client, server, and reverse =="
dart run tool/interop/boringssl/handshake.dart "$peer"
