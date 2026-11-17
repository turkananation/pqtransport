#!/usr/bin/env bash
# Upstream picoquicdemo against PqQuicConn.server. The demo does not
# offer ML-DSA-65. The flight exits 0 only when that refusal is what
# happened, including -M with one client port.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
demo="$(bash "$root/build.sh" | tail -n 1)"
openssl_lib="$(cd "$(dirname "$(bash "$repo/tool/interop/openssl/build.sh" | tail -n 1)")/../lib" && pwd)"
export LD_LIBRARY_PATH="${openssl_lib}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$repo"
exec dart run tool/interop/picoquic/quic_flight.dart "$demo"
