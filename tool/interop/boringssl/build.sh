#!/bin/sh
# Build BoringSSL 0.20261020.0 and link boringssl_verify.
# Skips the work when the pin's COMMIT file already matches.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repo=$(CDPATH= cd -- "$root/../../.." && pwd)
# shellcheck disable=SC1091
. "$root/pins.env"
prefix="$root/.build"
if [ -x "$prefix/bin/boringssl_verify" ] && [ -f "$prefix/COMMIT" ] \
  && [ "$(cat "$prefix/COMMIT")" = "$BORINGSSL_COMMIT" ]; then
  printf '%s\n' "$prefix/bin/boringssl_verify"
  exit 0
fi

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
src="$prefix/src"
mkdir -p "$src"
cd "$src"
if [ ! -d boringssl/.git ]; then
  git clone --depth 1 --branch "$BORINGSSL_TAG" \
    https://github.com/google/boringssl boringssl
fi
cd boringssl
got=$(git rev-parse HEAD)
if [ "$got" != "$BORINGSSL_COMMIT" ]; then
  echo "BoringSSL $BORINGSSL_TAG is $got, pin says $BORINGSSL_COMMIT" >&2
  exit 1
fi
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix"
ninja -C build bssl
cmake --install build
mkdir -p "$prefix/bin"
c++ -O2 -o "$prefix/bin/boringssl_verify" \
  "$root/boringssl_verify.c" \
  -I"$prefix/include" \
  "$prefix/lib/libcrypto.a" \
  -pthread
printf '%s\n' "$BORINGSSL_COMMIT" > "$prefix/COMMIT"
printf '%s\n' "$prefix/bin/boringssl_verify"
