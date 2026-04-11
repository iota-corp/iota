import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from slack_helpers import slack_alert_context


def rule(event):
    # Only alert on the `ekm_logging_config_set` action
    return event.get("action") == "ekm_logging_config_set"


def alert_context(event):
    # TODO: Add details to the context
    return slack_alert_context(event)
