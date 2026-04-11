#!/usr/bin/env python3
"""One-shot port of upstream github_rules into iota (run from repo root)."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_imports import vendor_prefix  # noqa: E402
from upstream_rules import upstream_rules_root  # noqa: E402

SRC = upstream_rules_root() / "rules" / "github_rules"
AUDIT = ROOT / "rules" / "github_audit"
WEBHOOK = ROOT / "rules" / "github_webhook"

# From upstream YAML LogTypes
WEBHOOK_FILES = {
    "github_shai_hulud_repo_created.py",
    "github_malicious_pr_titles.py",
    "github_malicious_comment_content.py",
    "github_malicious_issue_pages.py",
    "github_pull_request_target_usage.py",
    "github_malicious_commit_content.py",
    "github_crossfork_workflow_run.py",
    "github_self_hosted_runner_used.py",
    "github_workflow_artifact_download.py",
    "github_workflow_skip_commits.py",
    "github_workflow_contains_checkout.py",
}

# Hand-maintained in iota (correlation_store); do not overwrite from upstream.
SKIP = {"github_repo_initial_access.py"}

HEADER = """import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
"""


def transform(text: str) -> str:
    p = vendor_prefix()
    text = text.replace(f"from {p}_base_helpers import deep_get\n", "")
    text = text.replace(f"from {p}_base_helpers import deep_get", "")
    text = re.sub(
        rf"from {p}_github_helpers import \(([^)]+)\)",
        lambda m: "from github_helpers import (" + m.group(1) + ")",
        text,
        flags=re.DOTALL,
    )
    text = text.replace(
        f"from {p}_github_helpers import ", "from github_helpers import "
    )
    text = re.sub(rf"from {p}_detection_helpers[^\n]+\n", "", text)
    text = text.replace("event.udm('actor_user')", "event.get('actor')")
    text = text.replace('event.udm("actor_user")', 'event.get("actor")')
    text = re.sub(r"event\.deep_get\(", "deep_get(event, ", text)
    if "deep_get(event," in text and "from iota_helpers import deep_get" not in text:
        if "from github_helpers import" in text:
            text = text.replace(
                "from github_helpers import",
                "from iota_helpers import deep_get\nfrom github_helpers import",
                1,
            )
        else:
            text = HEADER + "from iota_helpers import deep_get\n" + text
    elif not text.lstrip().startswith("import os"):
        text = HEADER + text
    if "from iota_helpers import deep_get" not in text and "deep_get(" in text:
        lines = text.split("\n")
        insert_at = 0
        for i, line in enumerate(lines):
            if line.startswith("from github_helpers"):
                lines.insert(i, "from iota_helpers import deep_get")
                break
            insert_at = i + 1
        else:
            lines.insert(insert_at, "from iota_helpers import deep_get")
        text = "\n".join(lines)

    text = text.replace("from unittest.mock import MagicMock\n", "")
    text = text.replace(
        "    global MONITORED_ACTIONS  # pylint: disable=global-statement\n"
        "    if isinstance(MONITORED_ACTIONS, MagicMock):\n"
        "        MONITORED_ACTIONS = json.loads(MONITORED_ACTIONS())  # pylint: disable=not-callable\n",
        "",
    )
    text = re.sub(r'\breturn "DEFAULT"\b', 'return "INFO"', text)
    text = re.sub(r'\breturn "LOW"\b', 'return "LOW"', text)
    text = re.sub(r'\breturn "HIGH"\b', 'return "HIGH"', text)
    text = re.sub(r'\breturn "MEDIUM"\b', 'return "MEDIUM"', text)
    text = re.sub(r'\breturn "CRITICAL"\b', 'return "CRITICAL"', text)
    return text


def main():
    if not SRC.is_dir():
        print(f"skip: {SRC} not found")
        return 1
    AUDIT.mkdir(parents=True, exist_ok=True)
    WEBHOOK.mkdir(parents=True, exist_ok=True)
    for path in sorted(SRC.glob("*.py")):
        name = path.name
        if name in SKIP:
            print(f"skip {name}")
            continue
        raw = path.read_text()
        out = transform(raw)
        if name in WEBHOOK_FILES:
            dest = WEBHOOK / name
        else:
            dest = AUDIT / name
        dest.write_text(out)
        print(f"wrote {dest.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
