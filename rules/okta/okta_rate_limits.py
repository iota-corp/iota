"""
Detect Okta rate limit / concurrency limit events (potential DoS or brute force).

Ported from Panther: RuleID Okta.Rate.Limits
"""

from fnmatch import fnmatch
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context

DETECTION_EVENTS = [
    "app.oauth2.client_id_rate_limit_warning",
    "application.integration.rate_limit_exceeded",
    "system.client.rate_limit.*",
    "system.client.concurrency_rate_limit.*",
    "system.operation.rate_limit.*",
    "system.org.rate_limit.*",
    "core.concurrency.org.limit.violation",
]


def rule(event):
    event_type = event.get("eventType", "")
    for pattern in DETECTION_EVENTS:
        if fnmatch(event_type, pattern) and "violation" in event_type.lower():
            return True
    return False


def title(event):
    actor = deep_get(event, "actor", "alternateId")
    if actor == "unknown":
        actor = deep_get(event, "actor", "displayName", default="<id-not-found>")
    actor_type = deep_get(event, "actor", "type", default="<type-not-found>")
    event_type = event.get("eventType", "")
    return f"Okta Rate Limit Event: [{event_type}] by [{actor}/{actor_type}]"


def severity():
    return "MEDIUM"


def dedup(event):
    return str(deep_get(event, "actor", "id") or event.get("uuid", ""))


def alert_context(event):
    return okta_alert_context(event)
