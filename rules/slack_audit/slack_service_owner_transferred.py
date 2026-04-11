import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "service_owner_transferred"


def title(event):
    previous_owner = deep_get(
        event, "actor", "user", "email", default="<UNKNOWN_PREVIOUS_OWNER>"
    )
    new_owner = deep_get(
        event, "entity", "user", "email", default="<UNKNOWN_NEW_OWNER>"
    )
    workspace = deep_get(
        event, "context", "location", "domain", default="<UNKNOWN_WORKSPACE>"
    )
    return (
        f"Slack: Primary Owner transferred for workspace [{workspace}] "
        f"from [{previous_owner}] to [{new_owner}] - Highest privilege transfer"
    )


def alert_context(event):
    return slack_alert_context(event)
