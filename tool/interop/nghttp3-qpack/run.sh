#!/usr/bin/env bash
# QPACK field-section round trip with libnghttp3 1.11.0.
# See README.md in this directory.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$dir/../../.." && pwd)"
cd "$root"

# stdout of build.sh is the executable path and nothing else. CMake's
# install log used to be captured with it, and the kernel rejected
# that string as the program name.
out="$("$dir/build.sh")"
bin="$(printf '%s\n' "$out" | tail -n 1)"
lines="$(printf '%s\n' "$out" | wc -l)"
if [[ "$lines" -ne 1 || ! -x "$bin" ]]; then
  echo "nghttp3 build.sh must print only the qpack_iov path" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

dart run tool/interop/nghttp3-qpack/roundtrip.dart encode "$work/ours.bin"
dart run tool/interop/nghttp3-qpack/roundtrip.dart headers >"$work/expect.txt"
"$bin" decode "$work/ours.bin" >"$work/decoded.txt"
cmp -s "$work/expect.txt" "$work/decoded.txt"

"$bin" encode "$work/expect.txt" "$work/theirs.bin" "$work/encoder.bin"
dart run tool/interop/nghttp3-qpack/roundtrip.dart decode \
  "$work/theirs.bin" "$work/encoder.bin" >"$work/back.txt"
cmp -s "$work/expect.txt" "$work/back.txt"
echo "nghttp3 QPACK round trip ok ($(wc -c <"$work/ours.bin") byte section)"
