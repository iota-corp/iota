import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "private_channel_converted_to_public"


def alert_context(event):
    return slack_alert_context(event)


def title(event):
    channel_name = deep_get(
        event, "entity", "channel", "name", default="<unknown_channel>"
    )
    name = deep_get(event, "actor", "user", "name", default="<unknown_user>")
    email = deep_get(event, "actor", "user", "email", default="<unknown_email>")
    return f"Slack private channel {channel_name} made public by {name} <{email}>"
