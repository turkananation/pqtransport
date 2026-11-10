#!/usr/bin/env bash
# Build OpenSSL's demos/quic/server against the 3.5.9 prefix.
# s_server has no -quic. The last line is the demo binary.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
prefix="$root/.build"
demo="$prefix/bin/ossl-quic-server"
version="3.5.9"
openssl_bin="$(bash "$root/build.sh" | tail -n 1)"
if [[ -x "$demo" && -f "$prefix/src/quic-server.c" && "$demo" -nt "$prefix/src/quic-server.c" ]]; then
  printf '%s\n' "$demo"
  exit 0
fi
if [[ ! -f "$prefix/src/quic-server.c" ]]; then
  src="$(mktemp -d)"
  trap 'rm -rf "$src"' EXIT
  url="https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/openssl-${version}"
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 "$url" -o "$src/openssl.tar.gz"
  # 3.5.9 nests the file. Older trees kept demos/quic/server.c.
  member="$(tar -tzf "$src/openssl.tar.gz" | grep -E '/demos/quic/server/server\.c$' | head -n 1)"
  if [[ -z "$member" ]]; then
    member="$(tar -tzf "$src/openssl.tar.gz" | grep -E '/demos/quic/server\.c$' | head -n 1)"
  fi
  if [[ -z "$member" ]]; then
    echo "demos/quic server.c is not in the OpenSSL ${version} archive" >&2
    exit 1
  fi
  tar -xzf "$src/openssl.tar.gz" -C "$src" "$member"
  mkdir -p "$prefix/src"
  cp "$src/$member" "$prefix/src/quic-server.c"
fi
cc -O2 -o "$demo" "$prefix/src/quic-server.c" \
  -I"$prefix/include" \
  -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" \
  -lssl -lcrypto >&2
printf '%s\n' "$demo"
