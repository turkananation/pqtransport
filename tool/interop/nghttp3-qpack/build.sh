#!/usr/bin/env bash
# Build libnghttp3 (pinned) and tool/interop/nghttp3-qpack/qpack_iov.
# Artifacts stay in .build/ and are not committed.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
ver="1.11.0"
prefix="$dir/.build/nghttp3"
bin="$dir/.build/bin/qpack_iov"
url="https://github.com/ngtcp2/nghttp3/releases/download/v${ver}/nghttp3-${ver}.tar.xz"

if [[ -x "$bin" && -f "$prefix/lib/libnghttp3.so" ]]; then
  echo "$bin"
  exit 0
fi

need() {
  if ! command -v "$1" >/dev/null; then
    echo "missing $1" >&2
    exit 1
  fi
}
need curl
need tar
need make
need gcc

mkdir -p "$dir/.build/src" "$dir/.build/bin"
tarball="$dir/.build/src/nghttp3-${ver}.tar.xz"
if [[ ! -f "$tarball" ]]; then
  curl -fsSL -o "$tarball" -L "$url"
fi
rm -rf "$dir/.build/src/nghttp3-${ver}"
# The release tarball may fail chown inside this sandbox. Files are
# still on disk; require configure to exist rather than tar's status.
set +e
tar --no-same-owner -xf "$tarball" -C "$dir/.build/src"
set -e
if [[ ! -f "$dir/.build/src/nghttp3-${ver}/configure" ]]; then
  echo "nghttp3 ${ver} did not extract" >&2
  exit 1
fi
cd "$dir/.build/src/nghttp3-${ver}"
./configure --prefix="$prefix" --disable-static >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null

gcc -O2 -Wall -Wextra -o "$bin" "$dir/qpack_iov.c" \
  -I"$prefix/include" \
  -L"$prefix/lib" -lnghttp3 \
  -Wl,-rpath,"$prefix/lib"
echo "$bin"
