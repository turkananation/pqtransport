#!/usr/bin/env bash
# QPACK field-section round trip with libnghttp3 1.11.0.
# See README.md in this directory.
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$dir/../../.." && pwd)"
cd "$root"

bin="$("$dir/build.sh")"
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
