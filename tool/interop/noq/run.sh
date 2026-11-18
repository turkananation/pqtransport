#!/usr/bin/env bash
# noq 1.5.0 (bb1c63ee), rustls 0.23.46, aws-lc-rs. ML-DSA-65 is checked
# by rustls. Multipath is initial_max_path_id 1. Not picoquic.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$root/../../.." && pwd)"
bin="$root/peer/target/release/pq_noq_client"
if ! cargo build --release --offline --manifest-path "$root/peer/Cargo.toml"; then
  cargo build --release --manifest-path "$root/peer/Cargo.toml"
fi
cd "$repo"
dart run tool/interop/noq/quic_flight.dart "$bin"
