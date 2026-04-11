import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from slack_helpers import slack_alert_context


def rule(event):
    return event.get("action") == "file_malicious_content_detected"


def title(event):
    uploader = deep_get(event, "actor", "user", "email", default="<UNKNOWN_USER>")
    workspace = deep_get(
        event, "context", "location", "domain", default="<UNKNOWN_WORKSPACE>"
    )
    return (
        f"Slack: Malicious file detected in Slack workspace [{workspace}] "
        f"uploaded by [{uploader}] - Potential malware or phishing attack"
    )


def alert_context(event):
    return slack_alert_context(event)
