#!/usr/bin/env bash
# Build libnghttp3 (pinned) and tool/interop/nghttp3-qpack/qpack_iov.
# Artifacts stay in .build/ and are not committed.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
ver="1.11.0"
prefix="$dir/.build/nghttp3"
bin="$dir/.build/bin/qpack_iov"
# The release asset lives on release-assets.githubusercontent.com.
# GitHub Actions gets HTTP 504 from that host. The tag archive is the
# same commit, and codeload.github.com answers it.
url="https://codeload.github.com/ngtcp2/nghttp3/tar.gz/refs/tags/v${ver}"

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
need cmake

mkdir -p "$dir/.build/src" "$dir/.build/bin"
tarball="$dir/.build/src/nghttp3-${ver}.tar.gz"
if [[ ! -f "$tarball" ]]; then
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o "$tarball" -L "$url"
fi
rm -rf "$dir/.build/src/nghttp3-${ver}"
# The archive may fail chown inside this sandbox. Files are still on
# disk; require CMakeLists.txt rather than tar's status.
set +e
tar --no-same-owner -xzf "$tarball" -C "$dir/.build/src"
set -e
src="$dir/.build/src/nghttp3-${ver}"
if [[ ! -f "$src/CMakeLists.txt" ]]; then
  echo "nghttp3 ${ver} did not extract" >&2
  exit 1
fi
cmake -S "$src" -B "$src/build" \
  -DENABLE_LIB_ONLY=ON \
  -DENABLE_STATIC_LIB=OFF \
  -DENABLE_SHARED_LIB=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix"
cmake --build "$src/build" -j"$(nproc)"
cmake --install "$src/build"

gcc -O2 -Wall -Wextra -o "$bin" "$dir/qpack_iov.c" \
  -I"$prefix/include" \
  -L"$prefix/lib" -lnghttp3 \
  -Wl,-rpath,"$prefix/lib"
echo "$bin"
