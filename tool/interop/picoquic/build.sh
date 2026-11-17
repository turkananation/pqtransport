#!/usr/bin/env bash
# picoquic 1.1.54.0 (tag v2026.11.16.f557eab) and the picotls commit
# that tag's CI pins. OpenSSL is 3.5.9 so the hybrid groups compile.
# Picotls still has no ML-DSA signature scheme. Prints the demo path.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
prefix="$root/.build"
pico_tag="v2026.11.16.f557eab"
ptls_commit="e446233b4100ebcdec60901c05bfb7f4cd369c5d"
demo="$prefix/picoquic/build/picoquicdemo"
if [[ -x "$demo" ]]; then
  printf '%s\n' "$demo"
  exit 0
fi
openssl_bin="$(bash "$repo/tool/interop/openssl/build.sh" | tail -n 1)"
openssl_root="$(cd "$(dirname "$openssl_bin")/.." && pwd)"
mkdir -p "$prefix"
if [[ ! -d "$prefix/picotls/.git" ]]; then
  git clone https://github.com/h2o/picotls "$prefix/picotls" >&2
  git -C "$prefix/picotls" checkout --detach "$ptls_commit" >&2
  git -C "$prefix/picotls" submodule update --init --depth 1 >&2
fi
if [[ ! -f "$prefix/picotls/libpicotls-core.a" ]]; then
  cmake -S "$prefix/picotls" -B "$prefix/picotls" \
    -DWITH_BROTLI=OFF -DWITH_FUSION=OFF \
    -DOPENSSL_ROOT_DIR="$openssl_root" >&2
  cmake --build "$prefix/picotls" -j"$(nproc)" >&2
fi
if [[ ! -d "$prefix/picoquic/picoquic" ]]; then
  curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 \
    "https://codeload.github.com/private-octopus/picoquic/tar.gz/refs/tags/${pico_tag}" \
    -o "$prefix/picoquic.tar.gz"
  tar -xzf "$prefix/picoquic.tar.gz" -C "$prefix"
  mv "$prefix/picoquic-${pico_tag#v}" "$prefix/picoquic"
fi
cmake -S "$prefix/picoquic" -B "$prefix/picoquic/build" \
  -DWITH_OPENSSL=ON \
  -DOPENSSL_ROOT_DIR="$openssl_root" \
  -Dpicoquic_BUILD_TESTS=OFF \
  -DBUILD_PICO_SIM=OFF \
  -DBUILD_HTTP=OFF \
  -DBUILD_PQBENCH=OFF \
  -DBUILD_LOGREADER=OFF >&2
cmake --build "$prefix/picoquic/build" --target picoquicdemo -j"$(nproc)" >&2
printf '%s\n' "$demo"
