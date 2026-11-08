#!/usr/bin/env bash
# Build OpenSSL 3.5.9 with X25519MLKEM768 into tool/interop/openssl/.build.
# Reuses OPENSSL_BIN when it is already OpenSSL 3.5 or newer.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
prefix="$root/.build"
version="3.5.9"
tarball="openssl-${version}.tar.gz"
# The release asset is release-assets.githubusercontent.com, which
# Actions answers with 504. The tag archive is the same commit.
url="https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/openssl-${version}"

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
curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 "$url" -o "$workdir/$tarball"
tar -xzf "$workdir/$tarball" -C "$workdir"
src="$workdir/openssl-openssl-${version}"
cd "$src"
./Configure "linux-$(uname -m)" \
  --prefix="$prefix" --libdir=lib shared no-tests \
  -Wl,-rpath,"$prefix/lib" >&2
make -j"$(nproc)" >&2
make install_sw >&2
is_new_enough "$prefix/bin/openssl"
printf '%s\n' "$prefix/bin/openssl"
