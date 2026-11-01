#!/usr/bin/env bash
# BoringSSL 0.20261020.0 TLS peer. X25519MLKEM768 only.
# Fails if a flight does not finish. No dart:ffi.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
verify="$(bash "$root/build.sh" | tail -n 1)"
peer="$(dirname "$verify")/boringssl_peer"
cd "$repo"
dart run tool/interop/boringssl/handshake.dart "$peer"
