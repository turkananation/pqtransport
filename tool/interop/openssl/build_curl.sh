#!/bin/sh
# curl linked to the OpenSSL this directory built. The system curl is not
# this peer: it does not have the RFC 10024 groups.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
prefix="$root/.build"
curl_prefix="$prefix/curl"
bin="$curl_prefix/bin/curl"
if [ -x "$bin" ]; then
  printf '%s\n' "$bin"
  exit 0
fi

openssl_bin=$(bash "$root/build.sh" | tail -n 1)
openssl_prefix=$(CDPATH= cd -- "$(dirname "$openssl_bin")/.." && pwd)
version=8.16.0
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
curl -fsSL -o "$workdir/curl.tar.gz" \
  "https://curl.se/download/curl-${version}.tar.gz"
tar -xzf "$workdir/curl.tar.gz" -C "$workdir"
cd "$workdir/curl-${version}"
./configure --prefix="$curl_prefix" \
  --with-openssl="$openssl_prefix" \
  --without-libpsl \
  --disable-ldap --disable-ldaps \
  --disable-shared \
  LDFLAGS="-Wl,-rpath,${openssl_prefix}/lib" >&2
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >&2
make install >&2
printf '%s\n' "$bin"
