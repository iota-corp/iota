import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))

from correlation_store import event_unix_ts, sliding_window_threshold_crossed
from iota_helpers import deep_get
from slack_helpers import slack_alert_context

# Upstream metadata: DedupPeriodMinutes 1440, Threshold 60
_WINDOW_SEC = 1440 * 60
_THRESHOLD = 60

DENIAL_OF_SERVICE_ACTIONS = [
    "bulk_session_reset_by_admin",
    "user_session_invalidated",
    "user_session_reset_by_admin",
]


def dedup_key(event):
    return "Slack.AuditLogs.ApplicationDoS" + str(
        deep_get(event, "entity", "user", "name", default="")
    )


def rule(event):
    if event.get("action") not in DENIAL_OF_SERVICE_ACTIONS:
        return False
    ts = event_unix_ts(event)
    return sliding_window_threshold_crossed(
        dedup_key(event), _WINDOW_SEC, _THRESHOLD, ts
    )


def title(event):
    admin = deep_get(event, "actor", "user", "email", default="<UNKNOWN_ADMIN>")
    target = deep_get(event, "entity", "user", "name", default="<UNKNOWN_USER>")
    action = event.get("action", "<UNKNOWN_ACTION>")
    return f"Slack: Potential DoS - Admin [{admin}] performed [{action}] on user [{target}]"


def dedup(event):
    return dedup_key(event)


def alert_context(event):
    return slack_alert_context(event)
