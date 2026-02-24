"""
Detect API key revocation in Okta.

Ported from Panther: RuleID Okta.APIKeyRevoked
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context


def rule(event):
    return (
        event.get("eventType") == "system.api_token.revoke"
        and deep_get(event, "outcome", "result") == "SUCCESS"
    )


def title(event):
    target = event.get("target", [{}])
    key_name = (
        target[0].get("displayName", "MISSING DISPLAY NAME")
        if target
        else "MISSING TARGET"
    )
    actor_name = deep_get(event, "actor", "displayName", default="<UNKNOWN>")
    actor_id = deep_get(event, "actor", "alternateId", default="<UNKNOWN>")
    return f"{actor_name} <{actor_id}> revoked API key - <{key_name}>"


def severity():
    return "INFO"


def dedup(event):
    return event.get("uuid", "") or deep_get(
        event, "debugContext", "debugData", "requestId", default=""
    )


def alert_context(event):
    return okta_alert_context(event)
