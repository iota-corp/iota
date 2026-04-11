import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def rule(event):
    return event.get("action") == "repo.create"


def title(event):
    return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."
