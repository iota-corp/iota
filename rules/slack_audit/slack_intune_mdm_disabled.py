import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "intune_disabled"


def title(event):
    actor = deep_get(event, "actor", "user", "email", default="<UNKNOWN_ACTOR>")
    workspace = deep_get(
        event, "context", "location", "domain", default="<UNKNOWN_WORKSPACE>"
    )
    return (
        f"Microsoft Intune: MDM disabled for Slack workspace [{workspace}] "
        f"by [{actor}] - Mobile security controls removed"
    )


def alert_context(event):
    return slack_alert_context(event)
