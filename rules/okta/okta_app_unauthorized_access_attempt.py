"""
Detect unauthorized access attempt to an Okta application.

Source RuleID (upstream): Okta.App.Unauthorized.Access.Attempt
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context


def rule(event):
    return event.get("eventType") == "app.generic.unauth_app_access_attempt"


def title(event):
    actor_id = deep_get(event, "actor", "alternateId", default="<id-not-found>")
    target_list = event.get("target", [{}])
    target_id = (
        target_list[0].get("alternateId", "<id-not-found>")
        if target_list
        else "<id-not-found>"
    )
    return f"[{actor_id}] attempted unauthorized access to [{target_id}]"


def severity():
    return "MEDIUM"


def dedup(event):
    return (
        event.get("uuid", "")
        or f"unauth-app-{deep_get(event, 'actor', 'id')}-{event.get('published', '')}"
    )


def alert_context(event):
    return okta_alert_context(event)
