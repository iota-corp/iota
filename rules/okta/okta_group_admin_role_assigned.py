"""
Detect admin privileges assigned to an Okta group.

Source RuleID (upstream): Okta.Group.Admin.Role.Assigned
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from okta_helpers import okta_alert_context


def rule(event):
    return event.get("eventType") == "group.privilege.grant"


def title(event):
    target_list = event.get("target", [{}])
    group_id = (
        target_list[0].get("alternateId", "<id-not-found>")
        if target_list
        else "<id-not-found>"
    )
    return f"Okta Admin Privileges Assigned to Group [{group_id}]"


def severity():
    return "INFO"


def dedup(event):
    return (
        event.get("uuid", "") or f"group.privilege.grant-{event.get('published', '')}"
    )


def alert_context(event):
    return okta_alert_context(event)
