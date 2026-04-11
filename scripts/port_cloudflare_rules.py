#!/usr/bin/env python3
"""Port upstream Cloudflare rules into iota (optional mirror under IOTA_UPSTREAM_RULES)."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_imports import vendor_prefix  # noqa: E402
from upstream_rules import upstream_rules_root  # noqa: E402

SRC = upstream_rules_root() / "rules" / "cloudflare_rules"
DEST = ROOT / "rules" / "cloudflare"

# Hand-maintained (sliding-window thresholds); do not overwrite from upstream.
SKIP = {
    "cloudflare_firewall_ddos.py",
    "cloudflare_httpreq_bot_high_volume.py",
}

HEADER = """import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
"""


def transform(text: str) -> str:
    p = vendor_prefix()
    text = text.replace(
        f"from {p}_cloudflare_helpers import ", "from cloudflare_helpers import "
    )
    text = re.sub(r'\breturn "DEFAULT"\b', 'return "INFO"', text)
    if not text.lstrip().startswith("import os"):
        text = HEADER + text
    return text


def main():
    if not SRC.is_dir():
        print(f"skip: {SRC} not found")
        return 1
    DEST.mkdir(parents=True, exist_ok=True)
    for path in sorted(SRC.glob("*.py")):
        if path.name in SKIP:
            print(f"skip {path.name}")
            continue
        (DEST / path.name).write_text(transform(path.read_text()))
        print(f"wrote {DEST / path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
