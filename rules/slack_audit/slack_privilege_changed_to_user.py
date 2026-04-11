import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "role_change_to_user"


def title(event):
    username = deep_get(event, "entity", "user", "name", default="<unknown-entity>")
    email = deep_get(event, "entity", "user", "email", default="<unknown-email>")

    return f"Slack {username}'s ({email}) role changed to User"


def alert_context(event):
    return slack_alert_context(event)
