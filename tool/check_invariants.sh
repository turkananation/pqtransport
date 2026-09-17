#!/usr/bin/env bash
# Deterministic invariant checks for a pqtransport tree.
# Usage: tool/check_invariants.sh [path-to-pqtransport-package]
set -euo pipefail

ROOT="${1:-.}"
fail=0

say() { printf '%s\n' "$*"; }
bad() { say "FAIL: $*"; fail=1; }
ok()  { say "OK:   $*"; }

if [[ ! -f "$ROOT/pubspec.yaml" ]]; then
  bad "no pubspec.yaml under $ROOT"
  exit 1
fi

# Comments that mention dart:ffi (to forbid it) are not imports.
if grep -RIn --include='*.dart' -E "import['\"][[:space:]]*dart:ffi" "$ROOT/lib" "$ROOT/test" >/dev/null 2>&1; then
  bad "dart:ffi import found"
else
  ok "no dart:ffi"
fi

if grep -RIn --include='*.dart' "SecureSocket\|dart:io' as io" "$ROOT/lib/pqtransport.dart" >/dev/null 2>&1; then
  bad "web barrel must not reference dart:io / SecureSocket"
else
  ok "web barrel looks IO-free"
fi

if ! grep -q "pqforge:" "$ROOT/pubspec.yaml"; then
  bad "pubspec.yaml missing pqforge"
else
  ok "pqforge depends"
fi

if ! grep -q "swissarmyknife:" "$ROOT/pubspec.yaml"; then
  bad "pubspec.yaml missing swissarmyknife"
else
  ok "swissarmyknife depends"
fi

lengths="$ROOT/lib/src/core/lengths.dart"
if [[ ! -f "$lengths" ]]; then
  bad "missing lib/src/core/lengths.dart"
else
  for n in 1184 1088 1216 1120 1249 1153 1952 3309 4587 4588; do
    if ! grep -q "$n" "$lengths"; then
      bad "lengths.dart missing $n"
    fi
  done
  ok "lengths.dart present"
fi

# Size literals outside lengths.dart are defects (heuristic).
if grep -RIn --include='*.dart' --exclude='lengths.dart' \
  -E '\b(1184|1216|1120|1249|1153|0x11EC|0x11EB)\b' \
  "$ROOT/lib" >/dev/null 2>&1; then
  bad "protocol size literals found outside lengths.dart"
  grep -RIn --include='*.dart' --exclude='lengths.dart' \
    -E '\b(1184|1216|1120|1249|1153|0x11EC|0x11EB)\b' "$ROOT/lib" || true
else
  ok "no stray size literals in lib/"
fi

# Positive claims only. Denials ("no CMVP claim") are required by the evidence boundary.
# Limit the scan to package surfaces so nested site/build HTML cannot false-positive.
if grep -RIn --include='*.md' --include='*.dart' \
  -E 'FIPS validated|CMVP validated|constant-time Dart|securely erased' \
  "$ROOT/lib" "$ROOT/test" "$ROOT/example" "$ROOT/doc" \
  "$ROOT/README.md" "$ROOT/CHANGELOG.md" "$ROOT/llms.txt" \
  >/dev/null 2>&1; then
  bad "forbidden claim language"
else
  ok "claim language"
fi

# site/ is a workspace member, not an excluded folder. The 201 CI errors were
# the root analyzer resolving site/lib against package:pqtransport (no jaspr).
# Hiding that with analyzer.exclude is forbidden. Pub workspaces give site
# its own package_config so dart analyze actually type-checks it.
if [[ -f "$ROOT/site/pubspec.yaml" ]]; then
  if grep -qE 'package:jaspr' "$ROOT/pubspec.yaml"; then
    bad "root pubspec must not depend on jaspr; that belongs in site/"
  else
    ok "root pubspec does not depend on jaspr"
  fi
  if grep -qE 'site/\*\*' "$ROOT/analysis_options.yaml"; then
    bad "do not analyzer.exclude site/**; it is a workspace package and must be analyzed"
  else
    ok "site/ is not hidden from the analyzer"
  fi
  if grep -qE '^workspace:' "$ROOT/pubspec.yaml" && grep -qE '^\s*-\s*site\s*$' "$ROOT/pubspec.yaml"; then
    ok "root pubspec workspace lists site"
  else
    bad "root pubspec must declare workspace: [site]"
  fi
  if grep -qE '^resolution:\s*workspace' "$ROOT/site/pubspec.yaml"; then
    ok "site/ uses resolution: workspace"
  else
    bad "site/pubspec.yaml must set resolution: workspace"
  fi
  if grep -qE '^publish_to:\s*none' "$ROOT/site/pubspec.yaml"; then
    ok "site/ is publish_to: none"
  else
    bad "site/ must be publish_to: none"
  fi
  if [[ -f "$ROOT/site/pubspec.lock" ]]; then
    bad "site/pubspec.lock must not exist; workspace lockfile is the root pubspec.lock"
  else
    ok "no stray site/pubspec.lock"
  fi
fi

exit "$fail"
