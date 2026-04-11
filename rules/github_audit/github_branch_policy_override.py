import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))


def rule(event):
    return event.get("action") == "protected_branch.policy_override"


def title(event):
    branch = event.get("branch", "<UNKNOWN_BRANCH>")
    return (
        f"A branch protection requirement in the repository"
        f" [{event.get('repo', '<UNKNOWN_REPO>')}]"
        f" was overridden by user [{event.get('actor')}]"
        f" on branch [{branch}]"
    )
