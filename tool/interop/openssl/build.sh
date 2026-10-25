#!/usr/bin/env bash
# Build OpenSSL 3.5.9 with X25519MLKEM768 into tool/interop/openssl/.build.
# Reuses OPENSSL_BIN when it is already OpenSSL 3.5 or newer.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
prefix="$root/.build"
version="3.5.9"
tarball="openssl-${version}.tar.gz"
url="https://github.com/openssl/openssl/releases/download/openssl-${version}/${tarball}"

is_new_enough() {
  local bin="$1"
  [[ -x "$bin" ]] || return 1
  local ver
  ver="$("$bin" version 2>/dev/null || true)"
  [[ "$ver" =~ OpenSSL\ 3\.([5-9]|[1-9][0-9]) ]]
}

if [[ -n "${OPENSSL_BIN:-}" ]] && is_new_enough "$OPENSSL_BIN"; then
  printf '%s\n' "$OPENSSL_BIN"
  exit 0
fi
if is_new_enough "$prefix/bin/openssl"; then
  printf '%s\n' "$prefix/bin/openssl"
  exit 0
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
curl -fsSL "$url" -o "$workdir/$tarball"
tar -xzf "$workdir/$tarball" -C "$workdir"
src="$workdir/openssl-${version}"
cd "$src"
./Configure "linux-$(uname -m)" \
  --prefix="$prefix" --libdir=lib shared no-tests \
  -Wl,-rpath,"$prefix/lib" >&2
make -j"$(nproc)" >&2
make install_sw >&2
is_new_enough "$prefix/bin/openssl"
printf '%s\n' "$prefix/bin/openssl"
