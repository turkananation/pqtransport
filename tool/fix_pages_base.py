#!/usr/bin/env python3
"""Prefix root-absolute hrefs with /pqtransport/ for GitHub project Pages.

jaspr_content emits TOC and heading anchors as href="/page#id". Those
resolve to turkananation.github.io/page, not
turkananation.github.io/pqtransport/page. Relative links and anything
already under /pqtransport/ are left alone.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BASE = "/pqtransport/"
HREF_RE = re.compile(r'href="/(?!pqtransport/)([^"]*)"')


def fix_text(text: str) -> str:
    return HREF_RE.sub(lambda match: f'href="{BASE}{match.group(1)}"', text)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    if not root.exists():
        print(f"missing {root}", file=sys.stderr)
        return 1
    changed = 0
    for path in root.rglob("*.html"):
        original = path.read_text(encoding="utf-8")
        updated = fix_text(original)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            changed += 1
            print(f"fixed {path}")
    print(f"rewrote {changed} html files under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
