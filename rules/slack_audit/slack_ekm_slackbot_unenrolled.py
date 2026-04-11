import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from slack_helpers import slack_alert_context


def rule(event):
    # Only alert on the `ekm_slackbot_unenroll_notification_sent` action
    return event.get("action") == "ekm_slackbot_unenroll_notification_sent"


def alert_context(event):
    return slack_alert_context(event)
