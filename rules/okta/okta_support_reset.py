"""
Detect password or MFA reset performed by Okta Support.

Ported from Panther: RuleID Okta.Support.Reset
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "helpers"))
from iota_helpers import deep_get
from okta_helpers import okta_alert_context, get_okta_target

OKTA_SUPPORT_RESET_EVENTS = [
    "user.account.reset_password",
    "user.mfa.factor.update",
    "system.mfa.factor.deactivate",
    "user.mfa.attempt_bypass",
]


def rule(event):
    if event.get("eventType") not in OKTA_SUPPORT_RESET_EVENTS:
        return False
    # Actor is system@okta.com, transaction id unknown, no user agent / geo = support session
    return (
        deep_get(event, "actor", "alternateId") == "system@okta.com"
        and deep_get(event, "transaction", "id") == "unknown"
        and deep_get(event, "client", "userAgent", "rawUserAgent") is None
        and deep_get(event, "client", "geographicalContext", "country") is None
    )


def title(event):
    target = get_okta_target(event)
    target_user = (
        target.get("alternateId") or target.get("displayName") or "<unknown-user>"
    )
    return f"Okta Support Reset Password or MFA for user {target_user}"


def severity():
    return "HIGH"


def dedup(event):
    return (
        event.get("uuid", "")
        or f"{event.get('eventType', '')}-{event.get('published', '')}"
    )


def alert_context(event):
    return okta_alert_context(event)
