"""
Detect all MFA factors reset for an Okta user.

Ported from Panther: RuleID Okta.User.MFA.Reset.All
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context


def rule(event):
    return event.get("eventType") == "user.mfa.factor.reset_all"


def title(event):
    target_list = event.get("target", [{}])
    target_id = (
        target_list[0].get("alternateId", "<id-not-found>")
        if target_list
        else "<id-not-found>"
    )
    actor = event.get("actor", {})
    actor_id = actor.get("alternateId", "<id-not-found>")
    return f"Okta: All MFA factors were reset for [{target_id}] by [{actor_id}]"


def severity():
    return "MEDIUM"


def dedup(event):
    return event.get("uuid", "") or deep_get(
        event, "debugContext", "debugData", "requestId", default=""
    )


def alert_context(event):
    return okta_alert_context(event)
