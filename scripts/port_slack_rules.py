#!/usr/bin/env python3
"""Port upstream Slack audit rules into iota (optional mirror under IOTA_UPSTREAM_RULES)."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_imports import vendor_prefix  # noqa: E402
from upstream_rules import upstream_rules_root  # noqa: E402

SRC = upstream_rules_root() / "rules" / "slack_rules"
DEST = ROOT / "rules" / "slack_audit"

# Hand-maintained (sliding-window threshold); do not overwrite from upstream.
SKIP = {"slack_application_dos.py"}

HEADER = """import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
"""


def transform(text: str) -> str:
    p = vendor_prefix()
    text = text.replace(f"from {p}_slack_helpers import ", "from slack_helpers import ")
    text = re.sub(r"event\.deep_get\(", "deep_get(event, ", text)
    text = re.sub(r'\breturn "DEFAULT"\b', 'return "INFO"', text)
    if "deep_get(event," in text and "from iota_helpers import deep_get" not in text:
        text = text.replace(
            "from slack_helpers import",
            "from iota_helpers import deep_get\nfrom slack_helpers import",
            1,
        )
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
        out = transform(path.read_text())
        (DEST / path.name).write_text(out)
        print(f"wrote {DEST / path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
