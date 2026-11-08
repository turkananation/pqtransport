#!/usr/bin/env bash
# Build libnghttp3 (pinned) and tool/interop/nghttp3-qpack/qpack_iov.
# Artifacts stay in .build/ and are not committed.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
ver="1.11.0"
prefix="$dir/.build/nghttp3"
bin="$dir/.build/bin/qpack_iov"
src="$dir/.build/src/nghttp3-${ver}"

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
need git
need cmake
need make
need gcc

# The release asset is release-assets.githubusercontent.com, which
# Actions answers with HTTP 504. The tag archive on codeload omits the
# sfparse submodule, so CMake then has no sfparse.c. Clone the tag.
if [[ ! -f "$src/lib/sfparse/sfparse.c" ]]; then
  rm -rf "$src"
  git clone --depth 1 --branch "v${ver}" --recurse-submodules \
    https://github.com/ngtcp2/nghttp3.git "$src"
fi
if [[ ! -f "$src/lib/sfparse/sfparse.c" ]]; then
  echo "nghttp3 ${ver} is missing lib/sfparse" >&2
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

mkdir -p "$dir/.build/bin"
gcc -O2 -Wall -Wextra -o "$bin" "$dir/qpack_iov.c" \
  -I"$prefix/include" \
  -L"$prefix/lib" -lnghttp3 \
  -Wl,-rpath,"$prefix/lib"
echo "$bin"
