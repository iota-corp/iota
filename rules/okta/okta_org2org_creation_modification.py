"""
Detect Org2Org application created or modified (potential impersonation abuse).

Ported from Panther: RuleID Okta.Org2org.Creation.Modification
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context, get_okta_target

APP_LIFECYCLE_EVENTS = (
    "application.lifecycle.update",
    "application.lifecycle.create",
    "application.lifecycle.activate",
)


def rule(event):
    if event.get("eventType") not in APP_LIFECYCLE_EVENTS:
        return False
    targets = event.get("target", []) or []
    for t in targets:
        if "Org2Org" in (t.get("displayName") or ""):
            return True
    return False


def title(event):
    action = (event.get("eventType") or "").split(".")[-1]
    target = get_okta_target(event)
    target_id = target.get("alternateId", "<alternateId-not-found>")
    actor_name = deep_get(
        event, "actor", "displayName", default="<displayName-not-found>"
    )
    actor_id = deep_get(
        event, "actor", "alternateId", default="<alternateId-not-found>"
    )
    return f"{actor_name} <{actor_id}> {action}d Org2Org app [{target_id}]"


def severity(event):
    return "HIGH" if "create" in (event.get("eventType") or "") else "MEDIUM"


def dedup(event):
    return (
        event.get("uuid", "")
        or f"org2org-{event.get('eventType', '')}-{event.get('published', '')}"
    )


def alert_context(event):
    return okta_alert_context(event)
