import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from iota_helpers import deep_get
from github_helpers import github_webhook_alert_context


def rule(event):
    if event.get("action") != "created":
        return False

    # Check if the repository description matches the Shai-Hulud indicator
    description = deep_get(event, "repository", "description", default="")
    return description == "Sha1-Hulud: The Second Coming."


def title(event):
    repo_name = deep_get(event, "repository", "full_name", default="<UNKNOWN_REPO>")
    user = deep_get(event, "sender", "login", default="<UNKNOWN_USER>")
    return f"Sha1-Hulud malicious repository [{repo_name}] created by compromised user [{user}]"


def alert_context(event):
    context = github_webhook_alert_context(event)
    return context
