#!/usr/bin/env bash
# curl 8.23.0 and libnghttp2 1.66.0, linked to the OpenSSL this repo builds.
# The system curl is not this peer. This curl has HTTP/2. It does not
# have HTTP/3, and its wss:// URL is not RFC 8441.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
openssl_bin="$(bash "$repo/tool/interop/openssl/build.sh" | tail -n 1)"
openssl_prefix="$(cd "$(dirname "$openssl_bin")/.." && pwd)"
prefix="$root/.build"
ng_prefix="$prefix/nghttp2"
curl_prefix="$prefix/curl"
curl_bin="$curl_prefix/bin/curl"
h2="$prefix/h2connect"
if [[ -x "$curl_bin" && -x "$h2" ]] && "$curl_bin" --version | grep -q 'libcurl/8.23.0 OpenSSL/3.5' && "$curl_bin" --version | grep -q 'nghttp2/1.66.0'; then
  printf '%s\n%s\n' "$curl_bin" "$h2"
  exit 0
fi
mkdir -p "$prefix"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o "$workdir/nghttp2.tar.gz" \
  https://github.com/nghttp2/nghttp2/releases/download/v1.66.0/nghttp2-1.66.0.tar.gz
tar --no-same-owner -xzf "$workdir/nghttp2.tar.gz" -C "$workdir"
(
  cd "$workdir/nghttp2-1.66.0"
  ./configure --prefix="$ng_prefix" --enable-lib-only --disable-shared >&2
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >&2
  make install >&2
)
curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o "$workdir/curl.tar.gz" \
  https://curl.se/download/curl-8.23.0.tar.gz
tar --no-same-owner -xzf "$workdir/curl.tar.gz" -C "$workdir"
(
  cd "$workdir/curl-8.23.0"
  ./configure --prefix="$curl_prefix" \
    --with-openssl="$openssl_prefix" \
    --with-nghttp2="$ng_prefix" \
    --without-libpsl \
    --disable-ldap --disable-ldaps \
    --disable-shared \
    LDFLAGS="-Wl,-rpath,${openssl_prefix}/lib" >&2
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >&2
  make install >&2
)
cc -O2 -o "$h2" "$root/h2connect.c" \
  -I"$ng_prefix/include" -I"$openssl_prefix/include" \
  "$ng_prefix/lib/libnghttp2.a" \
  "$openssl_prefix/lib/libssl.a" \
  "$openssl_prefix/lib/libcrypto.a" \
  -pthread -ldl
"$curl_bin" --version | head -n 2 >&2
printf '%s\n%s\n' "$curl_bin" "$h2"
