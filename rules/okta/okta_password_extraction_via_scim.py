"""
Detect cleartext user passwords extracted via SCIM app (credential theft).

Ported from Panther: RuleID Okta.Password.Extraction.via.SCIM
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context, get_okta_target


def rule(event):
    return event.get(
        "eventType"
    ) == "application.lifecycle.update" and "Pushing user passwords" in deep_get(
        event, "outcome", "reason", default=""
    )


def title(event):
    target = get_okta_target(event)
    target_id = target.get("alternateId", "<alternateId-not-found>")
    actor_name = deep_get(
        event, "actor", "displayName", default="<displayName-not-found>"
    )
    actor_id = deep_get(
        event, "actor", "alternateId", default="<alternateId-not-found>"
    )
    return f"{actor_name} <{actor_id}> extracted cleartext user passwords via SCIM app [{target_id}]"


def severity():
    return "HIGH"


def dedup(event):
    return event.get("uuid", "") or f"scim-password-{event.get('published', '')}"


def alert_context(event):
    return okta_alert_context(event)
