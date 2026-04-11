"""Resolve root directory for optional upstream analysis rule mirrors."""

import os
from pathlib import Path


def upstream_rules_root() -> Path:
    env = os.environ.get("IOTA_UPSTREAM_RULES")
    if env:
        return Path(env)
    return (
        Path(__file__).resolve().parents[1].parent
        / "redteamtools"
        / "upstream-analysis"
    )
