#!/usr/bin/env python3
"""Port upstream kubernetes_rules into iota (run from repo root)."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_imports import vendor_prefix  # noqa: E402
from upstream_rules import upstream_rules_root  # noqa: E402

SRC = upstream_rules_root() / "rules" / "kubernetes_rules"
DEST = ROOT / "rules" / "kubernetes"

# Hand-maintained (enrichment / get_ipinfo_asn); do not overwrite from upstream.
SKIP = {
    "k8s_ioc_activity.py",
    "k8s_system_principal_public_ip.py",
}

HEADER = """import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
"""


def transform(text: str) -> str:
    p = vendor_prefix()
    text = re.sub(
        rf"from {p}_kubernetes_helpers import \(([^)]+)\)",
        lambda m: "from kubernetes_helpers import (" + m.group(1) + ")",
        text,
        flags=re.DOTALL,
    )
    text = text.replace(
        f"from {p}_kubernetes_helpers import ", "from kubernetes_helpers import "
    )
    text = text.replace(
        f"from {p}_ipinfo_helpers import get_ipinfo_asn\n",
        "from kubernetes_helpers import get_ipinfo_asn\n",
    )
    text = re.sub(r"event\.udm\(\s*", "k8s_udm(event, ", text)
    text = re.sub(r"event\.deep_get\(", "deep_get(event, ", text)
    text = re.sub(r'\breturn "DEFAULT"\b', 'return "INFO"', text)

    needs_deep = "deep_get(event," in text
    needs_k8s = "k8s_udm(event," in text
    if needs_deep:
        line = "from iota_helpers import deep_get\n"
        if "from kubernetes_helpers import" in text:
            text = text.replace(
                "from kubernetes_helpers import",
                line + "from kubernetes_helpers import",
                1,
            )
        else:
            text = line + text
    if needs_k8s and "import k8s_udm" not in text:
        text = re.sub(
            r"from kubernetes_helpers import ",
            "from kubernetes_helpers import k8s_udm, ",
            text,
            count=1,
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
        raw = path.read_text()
        out = transform(raw)
        (DEST / path.name).write_text(out)
        print(f"wrote {DEST / path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
