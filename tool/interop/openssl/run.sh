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
cd "$repo"
dart run tool/interop/openssl/handshake.dart "$bin"
