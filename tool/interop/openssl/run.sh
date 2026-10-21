#!/usr/bin/env bash
# LIM-01: one X25519MLKEM768 handshake against OpenSSL 3.5+.
# Fails if the peer flight does not complete. No dart:ffi.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
bin="$(bash "$root/build.sh" | tail -n 1)"
lib="$(cd "$(dirname "$bin")/../lib" && pwd)"
export LD_LIBRARY_PATH="${lib}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_CONF="${OPENSSL_CONF:-$root/openssl.cnf}"
cd "$repo"
dart run tool/interop/openssl/handshake.dart "$bin"
