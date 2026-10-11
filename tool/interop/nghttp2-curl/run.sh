#!/usr/bin/env bash
# Live DoH POST and GET against curl's libnghttp2 HTTP/2 stack.
# See README.md in this directory.
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"

if ! command -v curl >/dev/null; then
  echo "curl is required" >&2
  exit 1
fi
if ! curl --version | grep -q 'nghttp2/'; then
  echo "curl is not linked to nghttp2" >&2
  curl --version >&2 || true
  exit 1
fi

work="$(mktemp -d)"
trap 'kill "$server_pid" 2>/dev/null || true; rm -rf "$work"' EXIT

dart run tool/interop/nghttp2-curl/doh_fixture.dart query >"$work/query.bin"
dart run tool/interop/nghttp2-curl/doh_fixture.dart answer >"$work/answer.bin"
b64="$(dart run tool/interop/nghttp2-curl/doh_fixture.dart b64)"

dart run tool/interop/nghttp2-curl/h2c_doh_server.dart 2 >"$work/server.out" 2>"$work/server.err" &
server_pid=$!

port=""
for _ in $(seq 1 50); do
  if grep -q '^ready ' "$work/server.out" 2>/dev/null; then
    port="$(awk '/^ready / {print $2; exit}' "$work/server.out")"
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "h2c server exited early" >&2
    cat "$work/server.err" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ -z "$port" ]]; then
  echo "h2c server did not become ready" >&2
  cat "$work/server.err" >&2 || true
  exit 1
fi

curl_common=(
  --http2-prior-knowledge
  --silent
  --show-error
  --max-time 10
  --output
)

set +e
curl "${curl_common[@]}" "$work/post.body" -D "$work/post.hdr" \
  -H "accept: application/dns-message" \
  -H "content-type: application/dns-message" \
  --data-binary @"$work/query.bin" \
  "http://127.0.0.1:${port}/dns-query"
post_rc=$?
curl "${curl_common[@]}" "$work/get.body" -D "$work/get.hdr" \
  -H "accept: application/dns-message" \
  "http://127.0.0.1:${port}/dns-query?dns=${b64}"
get_rc=$?
set -e

if [[ "$post_rc" -ne 0 || "$get_rc" -ne 0 ]]; then
  echo "curl failed post=$post_rc get=$get_rc" >&2
  echo "--- server stderr ---" >&2
  cat "$work/server.err" >&2 || true
  echo "--- post headers ---" >&2
  cat "$work/post.hdr" >&2 || true
  exit 1
fi

grep -qi '^content-type: application/dns-message' "$work/post.hdr"
grep -qi '^content-type: application/dns-message' "$work/get.hdr"
cmp -s "$work/post.body" "$work/answer.bin"
cmp -s "$work/get.body" "$work/answer.bin"
echo "nghttp2/curl DoH POST and GET ok (port ${port})"
