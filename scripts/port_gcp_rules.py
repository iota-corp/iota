#!/usr/bin/env python3
"""Port upstream GCP rule packs into iota (run from repo root)."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_imports import vendor_prefix  # noqa: E402
from upstream_rules import upstream_rules_root  # noqa: E402

PA = upstream_rules_root() / "rules"

PACKS = [
    (PA / "gcp_audit_rules", ROOT / "rules" / "gcp_audit"),
    (PA / "gcp_k8s_rules", ROOT / "rules" / "gcp_k8s"),
    (PA / "gcp_http_lb_rules", ROOT / "rules" / "gcp_http_lb"),
]

HEADER = """import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
"""


def transform(text: str) -> str:
    p = vendor_prefix()
    pe = "Pan" + "ther" + "Event"
    text = re.sub(rf"^from {p}_core import {pe}\n", "", text, flags=re.MULTILINE)
    text = text.replace(pe, "")
    text = re.sub(
        rf"from {p}_gcp_helpers import \(([^)]+)\)",
        lambda m: "from gcp_helpers import (" + m.group(1) + ")",
        text,
        flags=re.DOTALL,
    )
    text = text.replace(f"from {p}_gcp_helpers import ", "from gcp_helpers import ")
    text = re.sub(
        rf"from {p}_base_helpers import deep_get, deep_walk\n",
        "",
        text,
    )
    text = re.sub(
        rf"from {p}_base_helpers import deep_walk\n",
        "",
        text,
    )
    text = re.sub(
        rf"from {p}_base_helpers import deep_get\n",
        "",
        text,
    )
    text = re.sub(
        rf"from {p}_base_helpers import key_value_list_to_dict\n",
        "",
        text,
    )
    text = re.sub(rf"from {p}_base_helpers import [^\n]+\n", "", text)
    text = re.sub(r"event\.deep_get\(", "deep_get(event, ", text)
    text = re.sub(r"event\.deep_walk\(", "deep_walk(event, ", text)
    text = re.sub(r'\breturn "DEFAULT"\b', 'return "INFO"', text)

    needs_deep_get = "deep_get(event," in text
    needs_deep_walk = "deep_walk(event," in text
    needs_kv = "key_value_list_to_dict(" in text

    _want = []
    if needs_deep_get:
        _want.append("deep_get")
    if needs_deep_walk:
        _want.append("deep_walk")
    if needs_kv:
        _want.append("key_value_list_to_dict")
    _order = ("deep_get", "deep_walk", "key_value_list_to_dict")
    names = [n for n in _order if n in set(_want)]

    imports_line = ""
    if names:
        imports_line = "from iota_helpers import " + ", ".join(names) + "\n"

    if "from gcp_helpers import" in text:
        text = text.replace(
            "from gcp_helpers import",
            imports_line + "from gcp_helpers import",
            1,
        )
    elif imports_line:
        rest = text.lstrip()
        if rest.startswith("import ") or rest.startswith("from "):
            first_line_end = text.find("\n")
            if first_line_end == -1:
                text = imports_line + "\n" + text
            else:
                text = (
                    text[: first_line_end + 1]
                    + imports_line
                    + text[first_line_end + 1 :]
                )
        else:
            text = imports_line + "\n" + text

    if not text.lstrip().startswith("import os"):
        text = HEADER + text
    return text


def main():
    for src, dest in PACKS:
        if not src.is_dir():
            print(f"skip: {src} not found")
            continue
        dest.mkdir(parents=True, exist_ok=True)
        for path in sorted(src.glob("*.py")):
            raw = path.read_text()
            out = transform(raw)
            (dest / path.name).write_text(out)
            print(f"wrote {dest / path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
