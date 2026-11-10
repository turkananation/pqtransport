#!/usr/bin/env bash
# Build the quiche peer against the pinned BoringSSL.
# The last line is the executable. bssl itself has no QUIC transport.
# This binary is the QUIC stack and the HTTP/3 GET peer. Not curl --http3.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
pin="fa0e48072e945ff2da5bb9a21684f86a91f35877"
prefix="$root/.build"
src="$prefix/src/quiche"
out="$prefix/bin/quiche_peer"
bssl="$repo/tool/interop/boringssl/.build"
if [ ! -f "$bssl/lib/libssl.a" ] || [ ! -f "$bssl/include/openssl/x509v3.h" ]; then
  echo "pinned BoringSSL is not built ($bssl)" >&2
  exit 1
fi
if [ -z "${LIBCLANG_PATH:-}" ]; then
  for dir in /usr/lib/llvm-*/lib /usr/lib/x86_64-linux-gnu /tmp/llvm/usr/lib/llvm-15/lib; do
    if compgen -G "$dir/libclang.so*" >/dev/null 2>&1; then
      LIBCLANG_PATH="$dir"
      break
    fi
  done
fi
if [ -z "${LIBCLANG_PATH:-}" ]; then
  echo "libclang is required to bind the pinned BoringSSL" >&2
  exit 1
fi
export LIBCLANG_PATH
# libclang does not search gcc's builtin headers on its own.
gcc_inc="$(dirname "$(cc -print-file-name=include/stddef.h)")"
export BINDGEN_EXTRA_CLANG_ARGS="-I${gcc_inc}${BINDGEN_EXTRA_CLANG_ARGS:+ ${BINDGEN_EXTRA_CLANG_ARGS}}"
export BORING_BSSL_PATH="$bssl"
export BORING_BSSL_INCLUDE_PATH="$bssl/include"
if [ -d /tmp/cmake/bin ]; then
  PATH="/tmp/cmake/bin:$PATH"
  export PATH
fi

mkdir -p "$prefix/src" "$prefix/bin"
if [ ! -f "$src/quiche/Cargo.toml" ]; then
  rm -rf "$src"
  if [ -d /tmp/quiche/.git ] && [ "$(git -C /tmp/quiche rev-parse HEAD)" = "$pin" ]; then
    ln -s /tmp/quiche "$src"
  else
    git init -q "$src"
    git -C "$src" remote add origin https://github.com/cloudflare/quiche.git
    git -C "$src" fetch --depth 1 origin "$pin"
    git -C "$src" checkout --quiet FETCH_HEAD
  fi
fi
got="$(git -C "$src" rev-parse HEAD)"
if [ "$got" != "$pin" ]; then
  echo "quiche is $got, pin is $pin" >&2
  exit 1
fi
if [ -x "$out" ] && [ -f "$prefix/COMMIT" ] && [ "$(cat "$prefix/COMMIT")" = "$pin" ] \
  && [ "$out" -nt "$root/peer/src/main.rs" ] \
  && [ "$out" -nt "$root/peer/Cargo.toml" ]; then
  printf '%s\n' "$out"
  exit 0
fi
export CARGO_TARGET_DIR="$prefix/target"
cargo build --release --manifest-path "$root/peer/Cargo.toml"
install -m 0755 "$prefix/target/release/quiche_peer" "$out"
printf '%s\n' "$pin" > "$prefix/COMMIT"
printf '%s\n' "$out"
